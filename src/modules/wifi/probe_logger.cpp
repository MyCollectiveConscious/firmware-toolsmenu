#include "probe_logger.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "core/wifi/webInterface.h"
#include "core/wifi/wifi_common.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "nvs_flash.h"
#include <Arduino.h>
#include <FS.h>
#include <globals.h>
#include <map>
#include <vector>

namespace {
constexpr size_t PROBE_LOGGER_SSID_MAX_LEN = 32;
constexpr size_t PROBE_LOGGER_QUEUE_DEPTH = 48;
constexpr uint32_t PROBE_LOGGER_CHECKPOINT_EVENTS = 20;
constexpr uint32_t PROBE_LOGGER_CHECKPOINT_INTERVAL_MS = 5000;
constexpr uint32_t PROBE_LOGGER_CHANNEL_DWELL_MS = 250;

const uint8_t PROBE_LOGGER_CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
constexpr size_t PROBE_LOGGER_CHANNEL_COUNT = sizeof(PROBE_LOGGER_CHANNELS) / sizeof(PROBE_LOGGER_CHANNELS[0]);

struct ProbeLoggerEvent {
    char ssid[PROBE_LOGGER_SSID_MAX_LEN + 1];
};

struct ProbeLoggerState {
    QueueHandle_t queue = nullptr;
    FS *fs = nullptr;
    String logPath;
    std::map<String, uint32_t> ssidCounts;
    uint32_t totalProbes = 0;
    uint32_t pendingEvents = 0;
    uint32_t droppedEvents = 0;
    uint32_t lastCheckpoint = 0;
    uint32_t lastChannelChange = 0;
    size_t channelIndex = 0;
    bool screenDirty = true;
};

static ProbeLoggerState &state() {
    static ProbeLoggerState instance;
    return instance;
}

static volatile bool captureEnabled = false;

static bool isProbeRequest(const wifi_promiscuous_pkt_t *packet) {
    if (packet == nullptr || packet->rx_ctrl.sig_len < 26) return false;

    const uint8_t *frame = packet->payload;
    uint16_t frameControl = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);
    uint8_t frameType = (frameControl & 0x000C) >> 2;
    uint8_t frameSubType = (frameControl & 0x00F0) >> 4;
    return frameType == 0x00 && frameSubType == 0x04;
}

static bool queueProbeSSID(const wifi_promiscuous_pkt_t *packet) {
    const uint8_t *frame = packet->payload;
    const size_t frameLength = packet->rx_ctrl.sig_len;
    size_t position = 24;

    while (position + 2 <= frameLength) {
        uint8_t elementId = frame[position];
        uint8_t elementLength = frame[position + 1];
        position += 2;
        if (position + elementLength > frameLength) return false;

        if (elementId == 0) {
            // A zero-length SSID is a wildcard probe, not a usable SSID name.
            if (elementLength == 0) return false;

            ProbeLoggerEvent event = {};
            size_t outputLength = elementLength;
            if (outputLength > PROBE_LOGGER_SSID_MAX_LEN) outputLength = PROBE_LOGGER_SSID_MAX_LEN;

            bool hidden = true;
            for (size_t i = 0; i < outputLength; i++) {
                uint8_t character = frame[position + i];
                if (character != 0) hidden = false;
                // Keep each probe on one line even if an unusual SSID contains controls.
                event.ssid[i] = (character >= 0x20 && character != 0x7F) ? (char)character : '?';
            }
            if (hidden) return false;
            event.ssid[outputLength] = '\0';
            if (state().queue == nullptr || xQueueSend(state().queue, &event, 0) != pdTRUE) {
                state().droppedEvents++;
            }
            return true;
        }

        position += elementLength;
    }

    return false;
}

static void probeLoggerRxCallback(void *buffer, wifi_promiscuous_pkt_type_t type) {
    if (!captureEnabled || type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *packet = (const wifi_promiscuous_pkt_t *)buffer;
    if (!isProbeRequest(packet)) return;
    queueProbeSSID(packet);
}

static bool startProbeLoggerWifi() {
    cleanlyStopWebUiForWiFiFeature();
    ensureWifiPlatform();
    nvs_flash_init();

    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t error = esp_wifi_init(&config);
    if (error != ESP_OK && error != ESP_ERR_WIFI_INIT_STATE) {
        Serial.printf("[ProbeLogger] wifi_init: %s\n", esp_err_to_name(error));
        return false;
    }

    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    error = esp_wifi_set_mode(WIFI_MODE_STA);
    if (error != ESP_OK) {
        Serial.printf("[ProbeLogger] wifi_set_mode: %s\n", esp_err_to_name(error));
        return false;
    }

    error = esp_wifi_start();
    if (error != ESP_OK && error != ESP_ERR_WIFI_INIT_STATE) {
        Serial.printf("[ProbeLogger] wifi_start: %s\n", esp_err_to_name(error));
        return false;
    }

    // A connected station cannot hop channels reliably, so this tool remains passive and unassociated.
    esp_wifi_disconnect();
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    error = esp_wifi_set_promiscuous_filter(&filter);
    if (error != ESP_OK) {
        Serial.printf("[ProbeLogger] wifi_set_promiscuous_filter: %s\n", esp_err_to_name(error));
        return false;
    }

    state().channelIndex = 0;
    esp_wifi_set_channel(PROBE_LOGGER_CHANNELS[0], WIFI_SECOND_CHAN_NONE);
    error = esp_wifi_set_promiscuous_rx_cb(probeLoggerRxCallback);
    if (error != ESP_OK) {
        Serial.printf("[ProbeLogger] wifi_set_promiscuous_rx_cb: %s\n", esp_err_to_name(error));
        return false;
    }

    captureEnabled = true;
    error = esp_wifi_set_promiscuous(true);
    if (error != ESP_OK) {
        captureEnabled = false;
        esp_wifi_set_promiscuous_rx_cb(nullptr);
        Serial.printf("[ProbeLogger] wifi_set_promiscuous: %s\n", esp_err_to_name(error));
        return false;
    }

    state().lastChannelChange = millis();
    return true;
}

static void stopProbeLoggerWifi() {
    captureEnabled = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    vTaskDelay(pdMS_TO_TICKS(20));
    esp_wifi_stop();
    wifiDisconnect();
}

static bool openNextLogFile() {
    ProbeLoggerState &logger = state();
    logger.fs = nullptr;
    if (!getFsStorage(logger.fs) || logger.fs == nullptr) return false;

    if (!logger.fs->exists("/ProbeLogs") && !logger.fs->mkdir("/ProbeLogs")) return false;

    uint32_t instance = 1;
    do {
        logger.logPath = "/ProbeLogs/ProbeLog" + String(instance);
        instance++;
    } while (logger.fs->exists(logger.logPath));

    File file = logger.fs->open(logger.logPath, FILE_WRITE);
    if (!file) {
        logger.logPath = "";
        logger.fs = nullptr;
        return false;
    }
    file.close();
    return true;
}

static bool checkpointLog() {
    ProbeLoggerState &logger = state();
    if (logger.fs == nullptr || logger.logPath.isEmpty()) return false;

    File file = logger.fs->open(logger.logPath, FILE_WRITE);
    if (!file) {
        Serial.printf("[ProbeLogger] Cannot checkpoint %s\n", logger.logPath.c_str());
        return false;
    }

    for (const auto &entry : logger.ssidCounts) {
        file.printf("%s [Probed: %lu]\n", entry.first.c_str(), (unsigned long)entry.second);
    }
    file.close();
    logger.pendingEvents = 0;
    logger.lastCheckpoint = millis();
    return true;
}

static void processQueuedProbes() {
    ProbeLoggerState &logger = state();
    ProbeLoggerEvent event = {};
    while (logger.queue != nullptr && xQueueReceive(logger.queue, &event, 0) == pdTRUE) {
        String ssid(event.ssid);
        auto entry = logger.ssidCounts.find(ssid);
        if (entry == logger.ssidCounts.end()) logger.ssidCounts.emplace(ssid, 1);
        else entry->second++;

        logger.totalProbes++;
        logger.pendingEvents++;
        logger.screenDirty = true;
        if (logger.pendingEvents >= PROBE_LOGGER_CHECKPOINT_EVENTS ||
            millis() - logger.lastCheckpoint >= PROBE_LOGGER_CHECKPOINT_INTERVAL_MS) {
            checkpointLog();
        }
        event = {};
    }
}

static void drawProbeLoggerScreen() {
    ProbeLoggerState &logger = state();
    if (!logger.screenDirty) return;

    drawMainBorderWithTitle("Probe Logger");
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    padprintln("");
    padprintln("Unique SSIDs: " + String(logger.ssidCounts.size()));
    padprintln("Times Probed: " + String(logger.totalProbes));
    logger.screenDirty = false;
}

static void waitForLaunchInputRelease() {
    // The select press that opened this tool must not become its first control action.
    vTaskDelay(pdMS_TO_TICKS(250));
    while (SelPress || EscPress) {
        check(SelPress);
        check(EscPress);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

static void probeLoggerControlMenu(bool &leaveLogger, bool &restartLogger) {
    std::vector<Option> loggerOptions = {
        {"Main Menu", [&]() { leaveLogger = true; }},
        {"Restart", [&]() { restartLogger = true; }},
    };
    loopOptions(loggerOptions, MENU_TYPE_SUBMENU, "Probe Logger");
}

static bool startProbeLoggerInstance() {
    ProbeLoggerState &logger = state();
    captureEnabled = false;
    xQueueReset(logger.queue);
    logger.ssidCounts.clear();
    logger.totalProbes = 0;
    logger.pendingEvents = 0;
    logger.lastCheckpoint = millis();
    logger.screenDirty = true;

    if (!openNextLogFile()) return false;
    captureEnabled = true;
    return true;
}
} // namespace

void probe_logger_setup() {
    returnToMenu = false;
    ProbeLoggerState &logger = state();
    logger.queue = xQueueCreate(PROBE_LOGGER_QUEUE_DEPTH, sizeof(ProbeLoggerEvent));
    if (logger.queue == nullptr) {
        displayError("Probe logger queue failed", true);
        return;
    }

    if (!openNextLogFile()) {
        vQueueDelete(logger.queue);
        logger.queue = nullptr;
        displayError("Probe logger storage failed", true);
        return;
    }

    if (!startProbeLoggerWifi()) {
        stopProbeLoggerWifi();
        logger.logPath = "";
        logger.fs = nullptr;
        vQueueDelete(logger.queue);
        logger.queue = nullptr;
        displayError("Probe logger Wi-Fi failed", true);
        return;
    }

    logger.ssidCounts.clear();
    logger.totalProbes = 0;
    logger.pendingEvents = 0;
    logger.lastCheckpoint = millis();
    logger.lastChannelChange = millis();
    logger.screenDirty = true;
    drawProbeLoggerScreen();
    waitForLaunchInputRelease();

    bool leaveLogger = false;
    while (!leaveLogger) {
        processQueuedProbes();

        if (millis() - logger.lastChannelChange >= PROBE_LOGGER_CHANNEL_DWELL_MS) {
            logger.channelIndex = (logger.channelIndex + 1) % PROBE_LOGGER_CHANNEL_COUNT;
            esp_wifi_set_channel(PROBE_LOGGER_CHANNELS[logger.channelIndex], WIFI_SECOND_CHAN_NONE);
            logger.lastChannelChange = millis();
        }

        drawProbeLoggerScreen();

        // Probe Logger exits through its encoder menu so an unrelated global
        // return-to-menu or back-button event cannot stop a running capture.
        check(EscPress);
        if (check(SelPress)) {
            while (check(SelPress)) vTaskDelay(pdMS_TO_TICKS(1));

            bool restartLogger = false;
            probeLoggerControlMenu(leaveLogger, restartLogger);
            if (restartLogger && !leaveLogger) {
                checkpointLog();
                if (!startProbeLoggerInstance()) {
                    displayError("Probe logger restart failed", true);
                    leaveLogger = true;
                }
            }
            if (!leaveLogger) {
                logger.screenDirty = true;
                drawProbeLoggerScreen();
            }
        }

        vTaskDelay(pdMS_TO_TICKS(20));
    }

    processQueuedProbes();
    checkpointLog();
    stopProbeLoggerWifi();
    if (logger.queue != nullptr) {
        vQueueDelete(logger.queue);
        logger.queue = nullptr;
    }
    logger.fs = nullptr;
    logger.logPath = "";
    returnToMenu = false;
}
