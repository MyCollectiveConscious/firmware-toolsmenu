#include "rfid_unlock.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include <Arduino.h>
#include <FS.h>
#include <globals.h>
#define private public
#include <Adafruit_PN532.h>
#include "PN532.h"
#undef private
#include "core/bus_HAL.h"

namespace {
String unlockStatus = "Not Unlockable";
String attackStatus = "-";
String infoLine1 = "";
String infoLine2 = "";
String infoLine3 = "";
bool screenDirty = true;

void drawUnlockScreen() {
    if (!screenDirty) return;
    drawMainBorderWithTitle("RFID Unlock");
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    if (infoLine1.length()) padprintln(infoLine1);
    else padprintln("Waiting...");
    if (infoLine2.length()) padprintln(infoLine2);
    if (infoLine3.length()) padprintln(infoLine3);
    padprintln("");
    padprintln("Status: " + unlockStatus);
    padprintln("Attack: " + attackStatus);
    screenDirty = false;
}

bool openNextUnlockFile(FS* &fs, String &path, File &f) {
    fs = nullptr;
    if (!getFsStorage(fs) || fs == nullptr) return false;
    if (!fs->exists("/RFIDUnlock") && !fs->mkdir("/RFIDUnlock")) return false;
    int n=1;
    do { path = "/RFIDUnlock/RFID" + String(n++); } while(fs->exists(path));
    f = fs->open(path, FILE_WRITE);
    return (bool)f;
}

String typeToString(uint8_t sak) {
    if (sak == 0x08) return "Mifare Classic 1K";
    if (sak == 0x18) return "Mifare Classic 4K";
    if (sak == 0x09) return "Mifare Mini";
    if (sak == 0x00) return "Mifare Ultralight";
    if (sak == 0x20) return "Mifare DESFire";
    char buf[16]; snprintf(buf,sizeof(buf),"SAK %02X",sak); return String(buf);
}
}

void rfid_unlock_setup() {
    returnToMenu = false;
    unlockStatus = "Not Unlockable";
    attackStatus = "-";
    infoLine1 = "Waiting...";
    infoLine2 = "Hold card to reader";
    infoLine3 = "";
    screenDirty = true;
    drawUnlockScreen();
    vTaskDelay(pdMS_TO_TICKS(250));
    while(SelPress||EscPress){ check(SelPress); check(EscPress); vTaskDelay(10); }

    PN532 pn532(PN532::I2C);
    if (!pn532.begin()) {
        displayError("PN532 not found", true);
        return;
    }
    String savedUID, savedAtqa, savedSak, savedType;
    bool savedUnlockable = false;
    bool savedSuccess = false;
    String savedKeysInfo = "";

    enum State { WAIT, SHOW, ATTACK, DONE } state = WAIT;
    bool leave=false;
    bool hasCard=false;
    unsigned long waitStart=millis();

    while(!leave && !returnToMenu) {
        if (state==WAIT) {
            // poll for card with timeout to allow UI refresh
            bool found = pn532.nfc.startPassiveTargetIDDetection(PN532_MIFARE_ISO14443A);
            if (found) found = pn532.nfc.readDetectedPassiveTargetID();
            if (found) {
                // use Adafruit targetUid directly (public via #define private public)
                String uid, atqa, sak, type;
                {
                    char buf[32];
                    uid="";
                    for(int i=0;i<pn532.nfc.targetUid.size;i++){ snprintf(buf,sizeof(buf),"%02X", pn532.nfc.targetUid.uidByte[i]); uid+=String(buf); if(i+1<pn532.nfc.targetUid.size) uid+=":"; }
                    snprintf(buf,sizeof(buf),"%02X%02X", pn532.nfc.targetUid.atqaByte[1], pn532.nfc.targetUid.atqaByte[0]); atqa=String(buf);
                    snprintf(buf,sizeof(buf),"%02X", pn532.nfc.targetUid.sak); sak=String(buf);
                    type = typeToString(pn532.nfc.targetUid.sak);
                    // also populate pn532.uid for later read()
                    pn532.uid.size = pn532.nfc.targetUid.size;
                    for(int i=0;i<pn532.uid.size;i++) pn532.uid.uidByte[i]=pn532.nfc.targetUid.uidByte[i];
                    pn532.uid.sak = pn532.nfc.targetUid.sak;
                    pn532.uid.atqaByte[0]=pn532.nfc.targetUid.atqaByte[0];
                    pn532.uid.atqaByte[1]=pn532.nfc.targetUid.atqaByte[1];
                }
                infoLine1 = "UID: " + uid;
                infoLine2 = "ATQA:" + atqa + " SAK:" + sak;
                infoLine3 = "Type: " + type;
                // determine unlockable
                bool isClassic = (pn532.uid.sak==0x08 || pn532.uid.sak==0x18 || pn532.uid.sak==0x09);
                bool isUlC = false; // simplified: treat Ultralight as not unlockable for now unless C
                // Check Ultralight-C by trying known key? For now mark false
                if (isClassic) unlockStatus = "Unlockable";
                else if (isUlC) unlockStatus = "Unlockable";
                else unlockStatus = "Not Unlockable";
                savedUID=uid; savedAtqa=atqa; savedSak=sak; savedType=type;
                savedUnlockable = (unlockStatus=="Unlockable");
                attackStatus = "-";
                screenDirty=true;
                drawUnlockScreen();
                if (savedUnlockable) {
                    state = ATTACK;
                } else {
                    state = SHOW;
                }
                hasCard=true;
            } else {
                // keep waiting screen alive
                if (millis()-waitStart>500) { waitStart=millis(); screenDirty=true; drawUnlockScreen(); }
                if (check(EscPress)) break;
                if (check(SelPress)) {
                    while(check(SelPress)) vTaskDelay(10);
                    std::vector<Option> opts={{"Main Menu", [&](){ leave=true; }},{"Retry", [&](){ state=WAIT; infoLine1="Waiting..."; infoLine2="Hold card to reader"; infoLine3=""; unlockStatus="Not Unlockable"; attackStatus="-"; screenDirty=true; }}};
                    loopOptions(opts, MENU_TYPE_SUBMENU, "RFID Unlock");
                    if (!leave) { screenDirty=true; drawUnlockScreen(); }
                }
                vTaskDelay(20);
                continue;
            }
        }
        if (state==ATTACK) {
            infoLine1 = "Running the attack,";
            infoLine2 = "take cover!";
            infoLine3 = "";
            attackStatus = "Running...";
            screenDirty=true; drawUnlockScreen();
            // run dictionary attack via existing read path
            int res = pn532.read(PN532_MIFARE_ISO14443A);
            // read() internally tries dictionary; check pageReadSuccess
            if (res==PN532::SUCCESS && pn532.pageReadSuccess) {
                attackStatus = "Successful";
                savedSuccess = true;
                // collect keys info
                savedKeysInfo = pn532.strAllPages; // full dump for 1:1 clone
            } else {
                // fallback: if Classic but read failed, still try to mark failed
                attackStatus = "Failed";
                savedSuccess = false;
            }
            screenDirty=true; drawUnlockScreen();
            state = DONE;
            vTaskDelay(800);
        }
        if (state==SHOW || state==DONE) {
            // offer options
            bool doSave=false, doRetry=false;
            std::vector<Option> opts;
            if (state==DONE && savedSuccess) opts.push_back({"Save", [&](){ doSave=true; }});
            opts.push_back({"Retry", [&](){ doRetry=true; }});
            opts.push_back({"Quit", [&](){ leave=true; }});
            loopOptions(opts, MENU_TYPE_SUBMENU, "RFID Unlock");
            if (doSave) {
                FS* fs; String path; File f;
                if (openNextUnlockFile(fs, path, f)) {
                    f.println("RFID Unlock");
                    f.printf("UID: %s\n", savedUID.c_str());
                    f.printf("ATQA: %s SAK: %s\n", savedAtqa.c_str(), savedSak.c_str());
                    f.printf("Type: %s\n", savedType.c_str());
                    f.printf("Status: %s\n", unlockStatus.c_str());
                    f.printf("Attack: %s\n", attackStatus.c_str());
                    if (savedKeysInfo.length()) { f.println("--- DUMP ---"); f.println(savedKeysInfo); }
                    else { f.println("--- NO DUMP ---"); }
                    f.printf("Time: %lu ms\n", millis());
                    f.close();
                    // also write full clone file for 1:1 restore to magic card
                    String clonePath = path;
                    clonePath.replace("RFID", "RFIDClone");
                    File cf = fs->open(clonePath, FILE_WRITE);
                    if (cf) {
                        // write same header but with raw pages for clone helper
                        // Use Bruce's save format: just dump pages as is
                        cf.println(savedKeysInfo);
                        cf.close();
                        displaySuccess("Saved " + path + " + " + clonePath, true);
                    } else {
                        displaySuccess("Saved to " + path, true);
                    }
                } else {
                    displayError("Save failed", true);
                }
                // after save, go to retry/quit
                doRetry=true;
            }
            if (doRetry) {
                state=WAIT;
                infoLine1="Waiting..."; infoLine2="Hold card to reader"; infoLine3="";
                unlockStatus="Not Unlockable"; attackStatus="-";
                hasCard=false;
                screenDirty=true; drawUnlockScreen();
                continue;
            }
            if (leave) break;
            if (check(EscPress)) break;
        }
        vTaskDelay(20);
        if (check(EscPress)) break;
        drawUnlockScreen();
    }
    returnToMenu=false;
}
