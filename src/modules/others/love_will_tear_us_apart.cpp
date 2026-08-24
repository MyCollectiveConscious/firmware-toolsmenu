#include "love_will_tear_us_apart.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "modules/others/audio.h"
#include <Arduino.h>
#include <FS.h>
#include <globals.h>

struct Lyric {
    int start; // seconds
    int end;
    const char* text;
};

static const Lyric lyrics[] = {
    {26,28, "When routine bites hard"},
    {29,31, "and ambitions are low"},
    {32,35, "And resentment rides high"},
    {36,38, "but emotions won't grow"},
    {39,41, "And we're changing our ways,"},
    {42,45, "taking different roads"},
    {46,52, "Love, love will tear us apart again"},
    {53,58, "Love, love will tear us apart again"},
    {64,67, "Why is the bedroom so cold"},
    {68,71, "turned away on your side?"},
    {72,74, "Is my timing that flawed,"},
    {75,77, "our respect run so dry?"},
    {78,81, "Yet there's still this appeal"},
    {82,84, "that we've kept through our lives"},
    {85,91, "Love, love will tear us apart again"},
    {92,97, "Love, love will tear us apart again"},
    {123,126, "Do you cry out in your sleep,"},
    {127,130, "all my failings exposed?"},
    {131,133, "Get a taste in my mouth"},
    {134,136, "as desperation takes hold"},
    {137,139, "Is it something so good"},
    {140,143, "just can't function no more?"},
    {144,149, "But love, love will tear us apart again"},
    {150,156, "Love, love will tear us apart again"},
    {157,163, "Love, love will tear us apart again"},
    {164,206, "Love, love will tear us apart again"},
};
static const int lyricCount = sizeof(lyrics)/sizeof(Lyric);
static const int songLenSec = 206; // 03:26

static String fmtTime(int sec) {
    char buf[6];
    int m = sec/60;
    int s = sec%60;
    snprintf(buf,sizeof(buf),"%02d:%02d",m,s);
    return String(buf);
}

void love_will_tear_us_apart_setup() {
    returnToMenu=false;
    FS* fs=nullptr;
    if (!getFsStorage(fs) || fs==nullptr) { displayError("No storage", true); return; }
    String audioPath = loopSD(*fs, true, "MP3|WAV|FLAC|M4A|AAC|OGG", "/");
    if (audioPath.length()==0 || audioPath=="\x1B" || !fs->exists(audioPath)) {
        displayError("No audio selected", true);
        return;
    }

    // start async playback
    bool ok = playAudioFile(fs, audioPath, PLAYBACK_ASYNC);
    if (!ok) {
        displayError("Audio play failed", true);
        return;
    }

    unsigned long start = millis();
    int curIdx = -1;
    int prevIdx = -1;
    int nextIdx = -1;
    bool wasPlaying = true;

    // exclusive screen loop until 03:26 or back button
    while(true) {
        if (check(EscPress)) { stopAudioPlayback(); break; }
        if (!isAudioPlaying()) {
            // if audio finished early, keep showing until timer ends
            wasPlaying = false;
        }
        unsigned long elapsed = (millis() - start)/1000;
        if (elapsed > (unsigned long)songLenSec) elapsed = songLenSec;

        // find current lyric
        int idx = -1;
        for(int i=0;i<lyricCount;i++){
            if (elapsed >= (unsigned)lyrics[i].start && elapsed < (unsigned)lyrics[i].end) { idx=i; break; }
            if (elapsed < (unsigned)lyrics[i].start) { break; }
        }
        // if between lyrics, idx stays -1 and we show last/next logic
        // Determine prev and next for display
        if (idx==-1) {
            // find next
            for(int i=0;i<lyricCount;i++) if (elapsed < (unsigned)lyrics[i].start) { nextIdx=i; break; }
            // prev is last that ended
            prevIdx=-1;
            for(int i=lyricCount-1;i>=0;i--) if ((unsigned)lyrics[i].end <= elapsed) { prevIdx=i; break; }
        } else {
            prevIdx = idx-1;
            nextIdx = idx+1;
            if (nextIdx>=lyricCount) nextIdx=-1;
        }

        // draw - 2-line centered layout as requested (remove top, keep middle + next)
        tft.fillScreen(TFT_BLACK);
        // timer at top centered
        {
            tft.setTextColor(TFT_WHITE, TFT_BLACK);
            tft.setTextSize(1);
            String timer = fmtTime(elapsed) + " / 03:26";
            int16_t w = tft.textWidth(timer, 2);
            tft.setCursor((tftWidth - w)/2, 6);
            tft.print(timer);
        }
        int midY = tftHeight/2;
        auto drawCentered = [&](const char* txt, int y, uint16_t color, uint8_t size){
            if(!txt || txt[0]=='\0') return;
            tft.setTextColor(color, TFT_BLACK);
            tft.setTextSize(size);
            String s = String(txt);
            int16_t w = tft.textWidth(s, 2);
            int16_t x = (tftWidth - w)/2;
            if(x<0) x=0;
            tft.setCursor(x, y);
            tft.print(s);
        };
        // middle: current line - large white, centered exactly like bottom/top (size 1 ensures full line fits)
        {
            String midText = (idx>=0) ? String(lyrics[idx].text) : String("");
            // use size 1 like bottom/top which are known to work fully - still stands out via white on black and center position
            drawCentered(midText.c_str(), midY - 8, TFT_WHITE, 1);
            // if you want it visually larger, increase font via FreeSansBold but keep size 1 for width correctness
        }
        // bottom: next line - smaller grey, like before
        if (nextIdx>=0) {
            drawCentered(lyrics[nextIdx].text, midY + 22, TFT_DARKGREY, 1);
        }

        if (elapsed >= (unsigned long)songLenSec) {
            // song ended
            vTaskDelay(1000);
            stopAudioPlayback();
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(80));
    }
    stopAudioPlayback();
    // clear and return
    tft.fillScreen(bruceConfig.bgColor);
    returnToMenu=false;
}
