#include "dns_logger.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "core/wifi/webInterface.h"
#include "core/wifi/wifi_common.h"
#include "esp_netif.h"
#include <ESPAsyncWebServer.h>
#include <Arduino.h>
#include <FS.h>
#include <WiFiUdp.h>
#include <globals.h>
#include <map>
#include <stdio.h>
#include <vector>

namespace {
constexpr size_t DNS_LOGGER_MAX_PACKET = 1024;
constexpr size_t DNS_LOGGER_MAX_PENDING = 8;
constexpr uint32_t DNS_LOGGER_PENDING_TIMEOUT_MS = 2000;
constexpr uint32_t DNS_LOGGER_FLUSH_EVENTS = 8;
constexpr uint32_t DNS_LOGGER_FLUSH_INTERVAL_MS = 5000;
constexpr uint16_t DNS_LOGGER_UPSTREAM_PORT = 53000;

const IPAddress DNS_LOGGER_AP_IP(192, 168, 50, 1);
const IPAddress DNS_LOGGER_AP_MASK(255, 255, 255, 0);
const IPAddress DNS_LOGGER_FALLBACK_DNS(1, 1, 1, 1);

struct PendingQuery {
    bool active = false;
    uint16_t internalId = 0;
    uint16_t clientId = 0;
    IPAddress clientIp;
    uint16_t clientPort = 0;
    uint32_t sentAt = 0;
};

struct DnsLoggerState {
    WiFiUDP clientUdp;
    WiFiUDP upstreamUdp;
    FS *fs = nullptr;
    File logFile;
    String logPath;
    String apSsid;
    String apPassword;
    String redirectPath;
    String portalPath;
    IPAddress upstreamDns;
    IPAddress normalUpstreamDns;
    PendingQuery pending[DNS_LOGGER_MAX_PENDING];
    std::map<String, uint32_t> domainCounts;
    std::map<String, IPAddress> redirectRecords;
    FS *portalFs = nullptr;
    AsyncWebServer *portalServer = nullptr;
    uint16_t nextInternalId = 0x8000;
    uint32_t totalQueries = 0;
    uint32_t pendingLogEvents = 0;
    uint32_t lastFlush = 0;
    bool screenDirty = true;
    bool redirectActive = false;
};

static DnsLoggerState &state() {
    static DnsLoggerState instance;
    return instance;
}

static const char *dnsTypeName(uint16_t type) {
    switch (type) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 65: return "HTTPS";
        default: return "OTHER";
    }
}

static bool readDnsQuestion(
    const uint8_t *packet, size_t length, String &name, uint16_t &type, size_t &questionEnd
) {
    if (packet == nullptr || length < 12) return false;
    uint16_t questionCount = ((uint16_t)packet[4] << 8) | packet[5];
    if (questionCount == 0) return false;

    size_t position = 12;
    name = "";
    while (position < length) {
        uint8_t labelLength = packet[position++];
        if (labelLength == 0) break;
        if ((labelLength & 0xC0) != 0 || labelLength > 63 || position + labelLength > length) return false;
        if (name.length() > 0) name += ".";
        for (size_t i = 0; i < labelLength; i++) {
            char character = (char)packet[position + i];
            if (character < 0x20 || character == 0x7F) character = '?';
            name += character;
        }
        position += labelLength;
    }

    if (name.isEmpty() || position + 4 > length) return false;
    type = ((uint16_t)packet[position] << 8) | packet[position + 1];
    questionEnd = position + 4;
    return true;
}

static String normalizeDomain(const String &value) {
    String domain = value;
    domain.trim();
    domain.toLowerCase();
    while (domain.endsWith(".")) domain.remove(domain.length() - 1);
    return domain;
}

static bool isCaptiveCheckDomain(const String &value) {
    String domain = normalizeDomain(value);
    static const char *const captiveCheckDomains[] = {
        "connectivitycheck.android.com",
        "connectivitycheck.gstatic.com",
        "clients3.google.com",
        "captive.apple.com",
        "www.apple.com",
        "www.msftconnecttest.com",
        "dns.msftncsi.com",
        "www.msftncsi.com",
        "detectportal.firefox.com",
        "nmcheck.gnome.org",
        "connectivity-check.ubuntu.com",
        "networkcheck.kde.org",
    };
    for (const char *checkDomain : captiveCheckDomains) {
        if (domain == checkDomain) return true;
    }
    return false;
}

static int findPending(uint16_t internalId) {
    for (size_t i = 0; i < DNS_LOGGER_MAX_PENDING; i++) {
        if (state().pending[i].active && state().pending[i].internalId == internalId) return (int)i;
    }
    return -1;
}

static int findFreePending() {
    for (size_t i = 0; i < DNS_LOGGER_MAX_PENDING; i++) {
        if (!state().pending[i].active) return (int)i;
    }
    return -1;
}

static bool openNextLogFile() {
    DnsLoggerState &logger = state();
    logger.fs = nullptr;
    if (!getFsStorage(logger.fs) || logger.fs == nullptr) return false;
    if (!logger.fs->exists("/DNSLogs") && !logger.fs->mkdir("/DNSLogs")) return false;

    uint32_t instance = 1;
    do {
        logger.logPath = "/DNSLogs/DNSLog" + String(instance++);
    } while (logger.fs->exists(logger.logPath));

    logger.logFile = logger.fs->open(logger.logPath, FILE_WRITE);
    if (!logger.logFile) {
        logger.logPath = "";
        logger.fs = nullptr;
        return false;
    }
    logger.lastFlush = millis();
    return true;
}

static void flushDnsLog() {
    DnsLoggerState &logger = state();
    if (!logger.logFile) return;
    logger.logFile.flush();
    logger.pendingLogEvents = 0;
    logger.lastFlush = millis();
}

static void logDnsQuery(const IPAddress &clientIp, const String &name, uint16_t type, const char *route) {
    DnsLoggerState &logger = state();
    logger.totalQueries++;
    logger.domainCounts[name]++;
    logger.screenDirty = true;

    if (logger.logFile) {
        logger.logFile.printf(
            "time_ms=%lu client=%s type=%s route=%s name=%s\n",
            (unsigned long)millis(),
            clientIp.toString().c_str(),
            dnsTypeName(type),
            route,
            name.c_str()
        );
        logger.pendingLogEvents++;
        if (logger.pendingLogEvents >= DNS_LOGGER_FLUSH_EVENTS ||
            millis() - logger.lastFlush >= DNS_LOGGER_FLUSH_INTERVAL_MS) {
            flushDnsLog();
        }
    }
}

static bool sendRedirectResponse(
    const uint8_t *request, size_t requestLength, size_t questionEnd, const IPAddress &clientIp, uint16_t clientPort,
    const IPAddress &redirectIp
) {
    if (request == nullptr || questionEnd > requestLength || questionEnd + 16 > DNS_LOGGER_MAX_PACKET) return false;

    uint8_t response[DNS_LOGGER_MAX_PACKET];
    memcpy(response, request, questionEnd);
    response[2] = 0x85; // response, authoritative answer, recursion desired/available
    response[3] = 0x80;
    response[4] = 0;
    response[5] = 1; // one question
    response[6] = 0;
    response[7] = 1; // one answer
    response[8] = response[9] = response[10] = response[11] = 0;

    size_t position = questionEnd;
    response[position++] = 0xC0;
    response[position++] = 0x0C; // pointer to the question name
    response[position++] = 0;
    response[position++] = 1; // A
    response[position++] = 0;
    response[position++] = 1; // IN
    response[position++] = 0;
    response[position++] = 0;
    response[position++] = 0;
    response[position++] = 60; // TTL
    response[position++] = 0;
    response[position++] = 4;
    for (int i = 0; i < 4; i++) response[position++] = redirectIp[i];

    DnsLoggerState &logger = state();
    if (logger.clientUdp.beginPacket(clientIp, clientPort) != 1) return false;
    logger.clientUdp.write(response, position);
    return logger.clientUdp.endPacket() == 1;
}

static bool loadRedirectFile() {
    DnsLoggerState &logger = state();
    FS *fs = nullptr;
    if (!getFsStorage(fs) || fs == nullptr) {
        displayError("No storage available", true);
        return false;
    }

    String selected = loopSD(*fs, true, "TXT");
    if (selected.isEmpty() || selected == "\x1B" || !fs->exists(selected)) return false;
    File file = fs->open(selected, FILE_READ);
    if (!file) {
        displayError("DNS record file failed", true);
        return false;
    }

    std::map<String, IPAddress> records;
    while (file.available()) {
        String line = file.readStringUntil('\n');
        line.trim();
        int comment = line.indexOf('#');
        if (comment >= 0) line = line.substring(0, comment);
        line.trim();
        if (line.isEmpty()) continue;

        char first[254] = {};
        char second[16] = {};
        char third[40] = {};
        int fields = sscanf(line.c_str(), "%253s %15s %39s", first, second, third);
        if (fields < 2) continue;

        const char *addressText = (fields == 2) ? second : third;
        if (fields == 3) {
            String recordType = second;
            recordType.toUpperCase();
            if (recordType != "A") continue;
        }

        IPAddress address;
        String domain = normalizeDomain(first);
        if (!domain.isEmpty() && address.fromString(addressText)) records[domain] = address;
    }
    file.close();

    if (records.empty()) {
        displayError("No valid A records", true);
        return false;
    }

    logger.redirectRecords = records;
    logger.redirectPath = selected;
    logger.redirectActive = true;
    logger.upstreamDns = DNS_LOGGER_FALLBACK_DNS;
    logger.screenDirty = true;
    Serial.printf(
        "[DNSLogger] Redirect records loaded: %s (%u entries), fallback=%s\n",
        selected.c_str(),
        (unsigned)logger.redirectRecords.size(),
        logger.upstreamDns.toString().c_str()
    );
    return true;
}

static void expirePendingQueries() {
    DnsLoggerState &logger = state();
    uint32_t now = millis();
    for (auto &query : logger.pending) {
        if (query.active && now - query.sentAt >= DNS_LOGGER_PENDING_TIMEOUT_MS) query.active = false;
    }
}

static void processClientQueries() {
    DnsLoggerState &logger = state();
    uint8_t packet[DNS_LOGGER_MAX_PACKET];

    while (true) {
        int packetLength = logger.clientUdp.parsePacket();
        if (packetLength <= 0) break;

        int readLength = logger.clientUdp.read(packet, sizeof(packet));
        if (readLength < 12) continue;

        IPAddress clientIp = logger.clientUdp.remoteIP();
        uint16_t clientPort = logger.clientUdp.remotePort();
        String name;
        uint16_t type = 0;
        size_t questionEnd = 0;
        bool validQuestion = readDnsQuestion(packet, readLength, name, type, questionEnd);
        if (validQuestion && type == 1 && questionEnd >= 2 && packet[questionEnd - 2] == 0 && packet[questionEnd - 1] == 1) {
            if (logger.portalServer != nullptr && isCaptiveCheckDomain(name) &&
                sendRedirectResponse(packet, readLength, questionEnd, clientIp, clientPort, DNS_LOGGER_AP_IP)) {
                logDnsQuery(clientIp, name, type, "portal");
                continue;
            }
            auto redirect = logger.redirectRecords.find(normalizeDomain(name));
            if (logger.redirectActive && redirect != logger.redirectRecords.end() &&
                sendRedirectResponse(packet, readLength, questionEnd, clientIp, clientPort, redirect->second)) {
                logDnsQuery(clientIp, name, type, "redirect");
                continue;
            }
        }
        if (validQuestion) logDnsQuery(clientIp, name, type, "upstream");

        int pendingIndex = findFreePending();
        if (pendingIndex < 0) continue;

        uint16_t clientId = ((uint16_t)packet[0] << 8) | packet[1];
        uint16_t internalId = logger.nextInternalId++;
        if (logger.nextInternalId == 0) logger.nextInternalId = 0x8000;
        packet[0] = (uint8_t)(internalId >> 8);
        packet[1] = (uint8_t)(internalId & 0xFF);

        if (logger.upstreamUdp.beginPacket(logger.upstreamDns, 53) != 1) continue;
        logger.upstreamUdp.write(packet, readLength);
        if (logger.upstreamUdp.endPacket() != 1) continue;

        PendingQuery &query = logger.pending[pendingIndex];
        query.active = true;
        query.internalId = internalId;
        query.clientId = clientId;
        query.clientIp = clientIp;
        query.clientPort = clientPort;
        query.sentAt = millis();
    }
}

static void processUpstreamResponses() {
    DnsLoggerState &logger = state();
    uint8_t packet[DNS_LOGGER_MAX_PACKET];

    while (true) {
        int packetLength = logger.upstreamUdp.parsePacket();
        if (packetLength <= 0) break;

        int readLength = logger.upstreamUdp.read(packet, sizeof(packet));
        if (readLength < 2) continue;
        uint16_t internalId = ((uint16_t)packet[0] << 8) | packet[1];
        int pendingIndex = findPending(internalId);
        if (pendingIndex < 0) continue;

        PendingQuery &query = logger.pending[pendingIndex];
        packet[0] = (uint8_t)(query.clientId >> 8);
        packet[1] = (uint8_t)(query.clientId & 0xFF);
        if (logger.clientUdp.beginPacket(query.clientIp, query.clientPort) == 1) {
            logger.clientUdp.write(packet, readLength);
            logger.clientUdp.endPacket();
        }
        query.active = false;
    }
}

static bool chooseApCredentials(String &ssid, String &password) {
    options = { {"Custom AP", [&]() { ssid = keyboard("Bruce-DNS-Logger", 30, "Bridged AP SSID:"); }} };
    for (const auto &storedName : bruceConfig.evilWifiNames) {
        options.push_back({storedName.c_str(), [&ssid, storedName]() { ssid = storedName; }});
    }
    loopOptions(options, MENU_TYPE_SUBMENU, "Bridged AP SSID");
    options.clear();
    if (ssid == "\x1B" || ssid.isEmpty()) return false;

    password = keyboard("", 63, "AP password (blank=open):", true);
    if (password == "\x1B") return false;
    if (!password.isEmpty() && password.length() < 8) {
        displayError("Password needs 8+ chars", true);
        return false;
    }
    return true;
}

static void stopCaptivePortal() {
    DnsLoggerState &logger = state();
    if (logger.portalServer != nullptr) {
        logger.portalServer->end();
        delete logger.portalServer;
        logger.portalServer = nullptr;
    }
    logger.portalFs = nullptr;
    logger.portalPath = "";
}

static bool sendCaptivePortalFile(AsyncWebServerRequest *request) {
    DnsLoggerState &logger = state();
    if (logger.portalFs == nullptr || logger.portalPath.isEmpty() || !logger.portalFs->exists(logger.portalPath)) {
        request->send(404, "text/plain", "Captive portal file unavailable");
        return false;
    }
    request->send(*logger.portalFs, logger.portalPath, "text/html");
    return true;
}

static bool configureCaptivePortal() {
    DnsLoggerState &logger = state();
    FS *fs = nullptr;
    if (!getFsStorage(fs) || fs == nullptr) {
        displayError("No storage available", true);
        return false;
    }

    String selected = loopSD(*fs, true, "HTML", "/");
    if (selected.isEmpty() || selected == "\x1B" || !fs->exists(selected)) return false;

    File file = fs->open(selected, FILE_READ);
    if (!file) {
        displayError("Captive HTML failed", true);
        return false;
    }
    file.close();

    stopCaptivePortal();
    logger.portalFs = fs;
    logger.portalPath = selected;
    logger.portalServer = new AsyncWebServer(80);
    if (logger.portalServer == nullptr) {
        logger.portalFs = nullptr;
        logger.portalPath = "";
        displayError("Captive server memory failed", true);
        return false;
    }

    logger.portalServer->on("/", HTTP_GET, [](AsyncWebServerRequest *request) { sendCaptivePortalFile(request); });
    logger.portalServer->on("/generate_204", HTTP_GET, [](AsyncWebServerRequest *request) { sendCaptivePortalFile(request); });
    logger.portalServer->on("/gen_204", HTTP_GET, [](AsyncWebServerRequest *request) { sendCaptivePortalFile(request); });
    logger.portalServer->on("/hotspot-detect.html", HTTP_GET, [](AsyncWebServerRequest *request) { sendCaptivePortalFile(request); });
    logger.portalServer->on("/ncsi.txt", HTTP_GET, [](AsyncWebServerRequest *request) { sendCaptivePortalFile(request); });
    logger.portalServer->on("/connecttest.txt", HTTP_GET, [](AsyncWebServerRequest *request) { sendCaptivePortalFile(request); });
    logger.portalServer->onNotFound([](AsyncWebServerRequest *request) { sendCaptivePortalFile(request); });
    logger.portalServer->begin();
    logger.screenDirty = true;
    Serial.printf("[DNSLogger] Captive portal active: %s\n", selected.c_str());
    return true;
}

static bool startDnsNetwork() {
    cleanlyStopWebUiForWiFiFeature();
    if (!WiFi.mode(WIFI_MODE_APSTA)) {
        Serial.println("[DNSLogger] Failed to enter APSTA mode");
        return false;
    }

    uint8_t channel = WiFi.channel();
    if (channel < 1 || channel > 13) channel = 1;

    if (!WiFi.softAPConfig(DNS_LOGGER_AP_IP, DNS_LOGGER_AP_IP, DNS_LOGGER_AP_MASK)) {
        Serial.println("[DNSLogger] softAPConfig failed");
        return false;
    }

    if (!WiFi.softAP(state().apSsid.c_str(), state().apPassword.c_str(), channel, 0, 4, false)) {
        Serial.println("[DNSLogger] softAP start failed");
        return false;
    }
    Serial.printf("[DNSLogger] SoftAP started: %s\n", WiFi.softAPIP().toString().c_str());

    esp_netif_t *apNetif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    esp_netif_t *staNetif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (apNetif == nullptr || staNetif == nullptr) {
        Serial.printf("[DNSLogger] netif lookup failed: AP=%p STA=%p\n", apNetif, staNetif);
        return false;
    }

    uint32_t waitStart = millis();
    while (!esp_netif_is_netif_up(apNetif) && millis() - waitStart < 2000) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    if (!esp_netif_is_netif_up(apNetif)) {
        Serial.println("[DNSLogger] AP netif did not become ready");
        return false;
    }

    esp_err_t error = esp_netif_napt_enable(apNetif);
    if (error != ESP_OK) {
        Serial.printf("[DNSLogger] NAPT enable failed: %s\n", esp_err_to_name(error));
        return false;
    }

    // APSTA normally selects the STA interface as the default route. A refusal
    // here should not prevent the already-enabled AP/NAPT path from starting.
    error = esp_netif_set_default_netif(staNetif);
    if (error != ESP_OK) {
        Serial.printf("[DNSLogger] STA default route unchanged: %s\n", esp_err_to_name(error));
    }

    DnsLoggerState &logger = state();
    logger.normalUpstreamDns = WiFi.dnsIP(0);
    if (logger.normalUpstreamDns == IPAddress(0, 0, 0, 0)) logger.normalUpstreamDns = DNS_LOGGER_FALLBACK_DNS;
    logger.upstreamDns = logger.normalUpstreamDns;
    Serial.printf(
        "[DNSLogger] AP=%s IP=%s upstream=%s gateway=%s DNS=%s NAPT=enabled\n",
        state().apSsid.c_str(),
        DNS_LOGGER_AP_IP.toString().c_str(),
        WiFi.localIP().toString().c_str(),
        WiFi.gatewayIP().toString().c_str(),
        logger.upstreamDns.toString().c_str()
    );
    if (logger.clientUdp.begin(DNS_LOGGER_AP_IP, 53) != 1) {
        Serial.println("[DNSLogger] Client DNS UDP bind failed");
        return false;
    }
    if (logger.upstreamUdp.begin(DNS_LOGGER_UPSTREAM_PORT) != 1) {
        Serial.println("[DNSLogger] Upstream DNS UDP bind failed");
        return false;
    }
    return true;
}

static void stopDnsNetwork(bool keepUpstream) {
    DnsLoggerState &logger = state();
    stopCaptivePortal();
    logger.clientUdp.stop();
    logger.upstreamUdp.stop();

    esp_netif_t *apNetif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (apNetif != nullptr) esp_netif_napt_disable(apNetif);
    WiFi.softAPdisconnect(true);
    if (keepUpstream) WiFi.mode(WIFI_MODE_STA);
    else wifiDisconnect();
}

static void drawDnsLoggerScreen() {
    DnsLoggerState &logger = state();
    if (!logger.screenDirty) return;
    drawMainBorderWithTitle("Bridged AP");
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    padprintln("AP: " + WiFi.softAPSSID());
    padprintln("Queries: " + String(logger.totalQueries));
    padprintln("Domains: " + String(logger.domainCounts.size()));
    padprintln(logger.redirectActive ? "DNS Redirection Active" : "DNS Redirection Not Active");
    padprintln(logger.portalServer != nullptr ? "Captive Portal Active" : "Captive Portal Not Active");
    logger.screenDirty = false;
}

static void waitForLaunchInputRelease() {
    vTaskDelay(pdMS_TO_TICKS(250));
    while (SelPress || EscPress) {
        check(SelPress);
        check(EscPress);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

static bool restartDnsLoggerInstance() {
    DnsLoggerState &logger = state();
    if (logger.logFile) {
        flushDnsLog();
        logger.logFile.close();
    }
    logger.domainCounts.clear();
    logger.redirectRecords.clear();
    logger.redirectPath = "";
    logger.redirectActive = false;
    stopCaptivePortal();
    logger.upstreamDns = logger.normalUpstreamDns;
    logger.totalQueries = 0;
    logger.pendingLogEvents = 0;
    for (auto &query : logger.pending) query.active = false;
    return openNextLogFile();
}
} // namespace

void dns_logger_setup() {
    returnToMenu = false;
    bool wasConnected = WiFi.isConnected();
    if (!wasConnected && (!wifiConnectMenu(WIFI_STA) || !WiFi.isConnected())) {
        displayError("Upstream Wi-Fi failed", true);
        return;
    }

    DnsLoggerState &logger = state();
    if (!chooseApCredentials(logger.apSsid, logger.apPassword)) {
        if (!wasConnected) wifiDisconnect();
        return;
    }

    if (!openNextLogFile()) {
        displayError("DNS logger storage failed", true);
        if (!wasConnected) wifiDisconnect();
        return;
    }

    if (!startDnsNetwork()) {
        if (logger.logFile) logger.logFile.close();
        logger.logPath = "";
        logger.fs = nullptr;
        stopDnsNetwork(wasConnected);
        displayError("DNS network setup failed", true);
        return;
    }

    logger.screenDirty = true;
    waitForLaunchInputRelease();
    drawDnsLoggerScreen();

    bool leaveLogger = false;
    while (!leaveLogger) {
        processClientQueries();
        processUpstreamResponses();
        expirePendingQueries();
        drawDnsLoggerScreen();

        check(EscPress);
        if (check(SelPress)) {
            while (check(SelPress)) vTaskDelay(pdMS_TO_TICKS(1));
            bool restartLogger = false;
            std::vector<Option> loggerOptions = {
                {"Main Menu", [&]() { leaveLogger = true; }},
                {"Restart", [&]() { restartLogger = true; }},
                {"DNS Redirect", loadRedirectFile},
                {"Captive Portal", configureCaptivePortal},
            };
            loopOptions(loggerOptions, MENU_TYPE_SUBMENU, "Bridged AP");
            if (restartLogger && !leaveLogger && !restartDnsLoggerInstance()) {
                displayError("DNS logger restart failed", true);
                leaveLogger = true;
            }
            if (!leaveLogger) {
                logger.screenDirty = true;
                drawDnsLoggerScreen();
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    flushDnsLog();
    if (logger.logFile) logger.logFile.close();
    stopDnsNetwork(wasConnected);
    logger.fs = nullptr;
    logger.logPath = "";
    returnToMenu = false;
}
