#include "rfid_watchdog.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include <Arduino.h>
#include <FS.h>
#include <globals.h>

// PN532 watchdog uses target mode directly via Adafruit_PN532
#define private public
#include <Adafruit_PN532.h>
#undef private
#include "core/bus_HAL.h"

namespace {
static FS *watchdogFs = nullptr;
static String watchdogPath;
static File watchdogFile;
static uint32_t watchdogEvents = 0;
static uint32_t watchdogAuths = 0;
static String watchdogLastHex = "-";
static String watchdogLastDecoded = "Waiting for reader...";
static String watchdogGuess = "Unknown";
static bool watchdogScreenDirty = true;
static String watchdogStatus = "Waiting...";

// helpers copied from PN532.cpp for standalone use
bool waitReadyPreferIrq(Adafruit_PN532 &nfc, uint16_t timeoutMs) {
    if (nfc._irq >= 0) {
        uint32_t start = millis();
        while (digitalRead(nfc._irq) != LOW) {
            if (timeoutMs != 0 && (millis() - start) > timeoutMs) return false;
            delay(1);
            yield();
        }
        return true;
    }
    return nfc.waitready(timeoutMs);
}
bool sendCommandCheckAckPreferIrq(Adafruit_PN532 &nfc, uint8_t *cmd, uint8_t cmdLen, uint16_t timeoutMs) {
    nfc.writecommand(cmd, cmdLen);
    delay(1);
    if (!waitReadyPreferIrq(nfc, timeoutMs)) return false;
    if (!nfc.readack()) return false;
    delay(1);
    if (!waitReadyPreferIrq(nfc, timeoutMs)) return false;
    return true;
}
bool setParametersIso14443_4Picc(Adafruit_PN532 &nfc) {
    uint8_t cmd[] = {PN532_COMMAND_SETPARAMETERS, 0x20};
    if (!sendCommandCheckAckPreferIrq(nfc, cmd, sizeof(cmd), 1000)) return false;
    uint8_t frame[8] = {0};
    nfc.readdata(frame, sizeof(frame));
    return true;
}
bool tgInitAsTargetIrq(
    Adafruit_PN532 &nfc, const uint8_t sensRes[2], const uint8_t nfcid1[3], const uint8_t nfcid2[8],
    const uint8_t pad[8], const uint8_t sysCode[2], bool piccOnly
) {
    uint8_t target[] = {
        PN532_COMMAND_TGINITASTARGET,
        static_cast<uint8_t>(piccOnly ? 0x04 : 0x01),
        sensRes[0], sensRes[1],
        nfcid1[0], nfcid1[1], nfcid1[2],
        static_cast<uint8_t>(piccOnly ? 0x20 : 0x00),
        nfcid2[0], nfcid2[1], nfcid2[2], nfcid2[3], nfcid2[4], nfcid2[5], nfcid2[6], nfcid2[7],
        pad[0], pad[1], pad[2], pad[3], pad[4], pad[5], pad[6], pad[7],
        sysCode[0], sysCode[1],
        0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00, 0x0E, 0x42, 0x52, 0x55, 0x43, 0x45, 0x20, 0x46, 0x49, 0x52, 0x4d, 0x57, 0x41, 0x52, 0x45
    };
    if (!sendCommandCheckAckPreferIrq(nfc, target, sizeof(target), 5000)) return false;
    uint8_t frame[8] = {0};
    nfc.readdata(frame, sizeof(frame));
    if (frame[6] == 0x15) return true;
    if (frame[6] == (PN532_COMMAND_TGINITASTARGET + 1)) {
        uint8_t status = frame[7];
        if (status == 0x04) { nfc.inRelease(); return false; }
        return status == 0x00 || status == 0x08 || status == 0x12 || status == 0x15 || status == 0x22;
    }
    return false;
}
bool tgGetDataIrq(Adafruit_PN532 &nfc, uint8_t *out, uint8_t maxLen, uint8_t *outLen, uint8_t *status) {
    uint8_t cmd = PN532_COMMAND_TGGETDATA;
    if (!sendCommandCheckAckPreferIrq(nfc, &cmd, 1, 1000)) return false;
    uint8_t frame[64] = {0};
    nfc.readdata(frame, sizeof(frame));
    if (frame[6] != (PN532_COMMAND_TGGETDATA + 1)) return false;
    *status = frame[7];
    uint8_t dataLen = frame[3] > 3 ? static_cast<uint8_t>(frame[3] - 3) : 0;
    uint8_t copyLen = std::min<uint8_t>(dataLen, maxLen);
    if (copyLen > 0) memcpy(out, frame + 8, copyLen);
    *outLen = copyLen;
    return true;
}
bool tgSetDataIrq(Adafruit_PN532 &nfc, const uint8_t *data, uint8_t dataLen) {
    if (dataLen == 0 || dataLen > 254) return false;
    uint8_t cmd[255] = {0};
    cmd[0] = PN532_COMMAND_TGSETDATA;
    memcpy(cmd + 1, data, dataLen);
    if (!sendCommandCheckAckPreferIrq(nfc, cmd, static_cast<uint8_t>(dataLen + 1), 1000)) return false;
    uint8_t frame[8] = {0};
    nfc.readdata(frame, sizeof(frame));
    if (frame[6] != (PN532_COMMAND_TGSETDATA + 1)) return false;
    return frame[7] == 0x00;
}

String bytesToHex(const uint8_t *data, uint8_t len) {
    String s;
    s.reserve(len * 3);
    for (uint8_t i = 0; i < len; i++) {
        if (i) s += ' ';
        char buf[4];
        snprintf(buf, sizeof(buf), "%02X", data[i]);
        s += buf;
    }
    return s;
}

String decodeReaderCommand(const uint8_t *data, uint8_t len) {
    if (len == 0) return "Empty";
    // ISO14443-4 RATS
    if (len >= 2 && data[0] == 0xE0 && data[1] == 0x80) return "RATS (ISO14443-4 / DESFire)";
    if (len >= 1 && data[0] == 0xE0) return "RATS variant";
    // Mifare Classic AUTH
    if (len >= 2 && (data[0] == 0x60 || data[0] == 0x61)) {
        char buf[48];
        snprintf(buf, sizeof(buf), "Mifare AUTH %s block %d", data[0]==0x60?"A":"B", data[1]);
        return String(buf);
    }
    // Mifare READ
    if (len >= 2 && data[0] == 0x30) {
        char buf[32];
        snprintf(buf, sizeof(buf), "READ block %d (Ultralight/Classic)", data[1]);
        return String(buf);
    }
    if (len >= 2 && data[0] == 0xA0) {
        char buf[32];
        snprintf(buf, sizeof(buf), "WRITE block %d", data[1]);
        return String(buf);
    }
    // SELECT AID (NDEF / EMV)
    if (len >= 5 && data[0]==0x00 && data[1]==0xA4) {
        // Check known AIDs
        if (len >= 12 && memcmp(data+5, "\xD2\x76\x00\x00\x85\x01\x01", 7)==0) return "SELECT NDEF AID (Type 4 Tag)";
        if (len >= 7 && memcmp(data+5, "\xA0\x00\x00\x00\x03", 5)==0) return "SELECT EMV / Payment AID";
        return "SELECT AID / File";
    }
    if (len >= 1 && data[0]==0x26) return "REQA (Type A poll)";
    if (len >= 1 && data[0]==0x52) return "WUPA (Wakeup)";
    if (len == 1 && data[0]==0x93) return "Anti-collision CL1";
    if (len == 5 && data[0]==0x50 && data[1]==0x00) return "HALT";
    // Generic APDU
    if (len >= 4 && data[0]==0x00) {
        char buf[48];
        snprintf(buf, sizeof(buf), "APDU INS=%02X P1=%02X P2=%02X", data[1], data[2], data[3]);
        return String(buf);
    }
    return "Unknown / proprietary";
}

String guessCardType(const String &decoded) {
    if (decoded.indexOf("AUTH") >= 0) return "Mifare Classic (Classic/Plus in SL1)";
    if (decoded.indexOf("RATS") >= 0) return "ISO14443-4 (DESFire / Plus SL2 / T4T)";
    if (decoded.indexOf("READ block") >= 0) return "Mifare Ultralight / NTAG (Type 2)";
    if (decoded.indexOf("SELECT NDEF") >= 0) return "NDEF Type 4 Tag";
    if (decoded.indexOf("SELECT EMV") >= 0) return "EMV Payment";
    if (decoded.indexOf("REQA") >= 0 || decoded.indexOf("WUPA") >= 0) return "ISO14443A poll";
    return "Generic 13.56MHz";
}

bool openNextLogFile() {
    watchdogFs = nullptr;
    if (!getFsStorage(watchdogFs) || watchdogFs == nullptr) return false;
    if (!watchdogFs->exists("/RFIDWatchdog") && !watchdogFs->mkdir("/RFIDWatchdog")) return false;
    uint32_t n = 1;
    do {
        watchdogPath = "/RFIDWatchdog/RFIDReader" + String(n++);
    } while (watchdogFs->exists(watchdogPath));
    watchdogFile = watchdogFs->open(watchdogPath, FILE_WRITE);
    if (!watchdogFile) { watchdogFs=nullptr; watchdogPath=""; return false; }
    watchdogFile.println("RFID Watchdog log");
    watchdogFile.println("Each line: raw reader -> card bytes + decoded meaning");
    watchdogFile.printf("Started: %lu ms\n", (unsigned long)millis());
    watchdogFile.println("---");
    watchdogFile.flush();
    return true;
}

void logReaderCommand(const uint8_t *data, uint8_t len) {
    if (!watchdogFile) return;
    String hex = bytesToHex(data, len);
    String decoded = decodeReaderCommand(data, len);
    watchdogFile.printf("[%lu ms] %s | %s\n", (unsigned long)millis(), hex.c_str(), decoded.c_str());
    watchdogFile.flush();
}

void drawWatchdogScreen() {
    if (!watchdogScreenDirty) return;
    drawMainBorderWithTitle("RFID Watchdog");
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    padprintln(watchdogStatus);
    padprintln("Events: " + String(watchdogEvents) + "  AUTHs: " + String(watchdogAuths));
    padprintln("Last: " + watchdogLastHex);
    // wrap decoded to fit
    String d = watchdogLastDecoded;
    if (d.length() > 32) d = d.substring(0,32);
    padprintln(d);
    padprintln("Guess: " + watchdogGuess);
    padprintln("");
    padprintln("Hold near reader");
    watchdogScreenDirty = false;
}

void waitForLaunchRelease() {
    vTaskDelay(pdMS_TO_TICKS(250));
    while (SelPress || EscPress) { check(SelPress); check(EscPress); vTaskDelay(pdMS_TO_TICKS(10)); }
}

bool startWatchdogInstance() {
    if (watchdogFile) { watchdogFile.flush(); watchdogFile.close(); }
    watchdogEvents = 0;
    watchdogAuths = 0;
    watchdogLastHex = "-";
    watchdogLastDecoded = "Waiting for reader...";
    watchdogGuess = "Unknown";
    watchdogStatus = "Waiting...";
    watchdogScreenDirty = true;
    return openNextLogFile();
}

} // namespace

void rfid_watchdog_setup() {
    returnToMenu = false;

    if (!openNextLogFile()) {
        displayError("RFID log storage failed", true);
        return;
    }

    // Setup display initial
    watchdogScreenDirty = true;
    drawWatchdogScreen();
    waitForLaunchRelease();

    // Init PN532
    Adafruit_PN532 nfc = Adafruit_PN532(PN532_IRQ, PN532_RF_REST);
    // Use same pins as global PN532
    // The global PN532 instance in Bruce uses bruceConfigPins; we mirror that by reusing its interface
    // For I2C mode we must ensure bus is acquired similar to PN532::begin
    bool useI2C = true; // T-Embed CC1101 uses I2C
    TwoWire *WireBus = acquireI2CBus();
    if (WireBus) {
        WireBus->setClock(100000);
        WireBus->setTimeOut(50);
    }
    // Reset/wakeup sequence similar to PN532::emulate
    nfc.begin();
    uint32_t ver = nfc.getFirmwareVersion();
    if (ver == 0) {
        displayError("PN532 not found", true);
        if (watchdogFile) watchdogFile.close();
        return;
    }
    // reset to clear SAM
    nfc.reset();
    delay(10);
    nfc.wakeup();
    setParametersIso14443_4Picc(nfc);

    // Prepare target identity: generic Mifare Classic 1K friendly
    uint8_t sensRes[2] = {0x04, 0x00}; // ATQA for Classic 1K
    uint8_t nfcid1[3] = {0xA1, 0xB2, 0xC3}; // last 3 bytes of 4-byte UID (first byte fixed 0x08 by PN532)
    uint8_t nfcid2[8] = {0x01,0xFE,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7};
    uint8_t pad[8]    = {0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7};
    uint8_t sysCode[2]= {0xFF,0xFF};

    bool targetReady = false;
    uint32_t nextArmTry = 0;
    watchdogStatus = "Arming...";
    watchdogScreenDirty = true;
    drawWatchdogScreen();

    bool leaveWatchdog = false;
    while (!leaveWatchdog) {
        // arm if needed
        if (!targetReady && millis() >= nextArmTry) {
            targetReady = tgInitAsTargetIrq(nfc, sensRes, nfcid1, nfcid2, pad, sysCode, false);
            nextArmTry = millis() + 300;
            if (targetReady) {
                watchdogStatus = "Emulating - hold to reader";
                watchdogScreenDirty = true;
            }
            if (!targetReady) { vTaskDelay(pdMS_TO_TICKS(20)); }
        }
        if (!targetReady) {
            // allow UI and input
            if (check(EscPress)) break;
            if (check(SelPress)) {
                while(check(SelPress)) vTaskDelay(pdMS_TO_TICKS(1));
                bool restart=false;
                std::vector<Option> opts = {
                    {"Main Menu", [&](){ leaveWatchdog=true; }},
                    {"Restart", [&](){ restart=true; }},
                };
                loopOptions(opts, MENU_TYPE_SUBMENU, "RFID Watchdog");
                if (restart && !leaveWatchdog) {
                    nfc.inRelease();
                    targetReady=false;
                    if (!startWatchdogInstance()) { displayError("Restart log failed", true); leaveWatchdog=true; }
                }
                watchdogScreenDirty=true;
                drawWatchdogScreen();
            }
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        uint8_t req[64]={0};
        uint8_t reqLen=0;
        uint8_t status=0xFF;
        bool got = tgGetDataIrq(nfc, req, sizeof(req), &reqLen, &status);
        for (uint8_t r=0; !got && r<2; r++) { delay(30); got = tgGetDataIrq(nfc, req, sizeof(req), &reqLen, &status); }

        if (!got) {
            nfc.inRelease();
            targetReady=false;
            watchdogStatus="Re-arming...";
            watchdogScreenDirty=true;
            delay(20);
            continue;
        }
        if (status==0x29) { // released
            nfc.inRelease();
            targetReady=false;
            watchdogStatus="Reader left - re-arming";
            watchdogScreenDirty=true;
            delay(20);
            continue;
        }
        if (status!=0x00 || reqLen<1) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        // Got a reader command
        watchdogEvents++;
        if (req[0]==0x60 || req[0]==0x61) watchdogAuths++;
        watchdogLastHex = bytesToHex(req, reqLen);
        watchdogLastDecoded = decodeReaderCommand(req, reqLen);
        watchdogGuess = guessCardType(watchdogLastDecoded);
        watchdogStatus = "Reader detected!";
        watchdogScreenDirty = true;
        logReaderCommand(req, reqLen);
        drawWatchdogScreen();

        // Respond to keep reader engaged where possible
        // For RATS, send a minimal ATS; for AUTH/READ etc, send NACK to avoid crypto errors but still log
        uint8_t respNack[1] = {0x04};
        uint8_t ats[6] = {0x05, 0x78, 0x80, 0x70, 0x02, 0x00}; // minimal ATS from ST25R example
        bool isRats = (reqLen>=2 && req[0]==0xE0);
        if (isRats) {
            tgSetDataIrq(nfc, ats, sizeof(ats));
        } else if (req[0]==0x60 || req[0]==0x61) {
            // Send dummy Nt (4 bytes) to let reader continue to second auth step
            uint8_t dummyNt[4] = {0x01,0x02,0x03,0x04};
            tgSetDataIrq(nfc, dummyNt, sizeof(dummyNt));
        } else {
            tgSetDataIrq(nfc, respNack, sizeof(respNack));
        }

        // Check controls after each exchange
        if (check(EscPress)) break;
        if (check(SelPress)) {
            while(check(SelPress)) vTaskDelay(pdMS_TO_TICKS(1));
            bool restart=false;
            std::vector<Option> opts = {
                {"Main Menu", [&](){ leaveWatchdog=true; }},
                {"Restart", [&](){ restart=true; }},
            };
            loopOptions(opts, MENU_TYPE_SUBMENU, "RFID Watchdog");
            if (restart && !leaveWatchdog) {
                nfc.inRelease();
                targetReady=false;
                if (!startWatchdogInstance()) { displayError("Restart log failed", true); leaveWatchdog=true; }
            }
            watchdogScreenDirty=true;
            drawWatchdogScreen();
        }
        vTaskDelay(pdMS_TO_TICKS(10));
        // keep targetReady true; next TgGetData will fetch next command
    }

    // cleanup
    nfc.inRelease();
    if (watchdogFile) { watchdogFile.flush(); watchdogFile.close(); }
    watchdogFs = nullptr;
    watchdogPath = "";
    returnToMenu = false;
}
