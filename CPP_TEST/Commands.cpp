// Commands.cpp

#include "Commands.h"
#include "TelegramApi.h"
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <iostream> // cout을 위해 추가
#include <sstream>  // stringstream을 위해 추가

static std::unordered_map<std::string, CmdHandler> g_cmds;
static std::mutex g_m;

// ??? 수정된 RegisterCommand 함수 ???
void RegisterCommand(const std::string& name, CmdHandler handler) {
    std::lock_guard<std::mutex> lk(g_m);
    g_cmds[name] = std::move(handler);
    // 등록 로그 추가
    std::cout << "[DEBUG] ==> '" << name << "' command registered." << std::endl;
}

bool StartsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), s.begin());
}

// ??? 수정된 DispatchCommand 함수 ???
bool DispatchCommand(long long chatId, const std::string& hwid8,
    const std::string& fullLineUtf8) {

    // 1. 명령어 파싱 (기존과 동일)
    const std::string head = "/" + hwid8 + " ";
    if (!StartsWith(fullLineUtf8, head)) {
        // 이 봇을 향한 명령이 아니므로 조용히 무시 (false 반환)
        return false;
    }

    size_t p = head.size();
    size_t q = fullLineUtf8.find(' ', p);
    std::string cmd = (q == std::string::npos) ? fullLineUtf8.substr(p) : fullLineUtf8.substr(p, q - p);
    std::string args = (q == std::string::npos) ? "" : fullLineUtf8.substr(q + 1);

    // 2. 명령어 핸들러 검색 (기존과 동일)
    CmdHandler h = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_m);
        auto it = g_cmds.find(cmd);
        if (it != g_cmds.end()) {
            h = it->second;
        }
    }

    // 3. 핸들러 실행 또는 "명령어 없음" 메시지 전송 (핵심 변경 부분)
    if (h) {
        // 핸들러가 있으면 실행
        h(chatId, hwid8, args);
        return true; // 성공적으로 처리했음을 알림
    }
    else {
        // 핸들러가 없으면, 사용자에게 알림 메시지 전송
        std::wstringstream wss;
        wss << L"⚠️ *명령어 처리 실패* ⚠️\n";
        wss << L"────────────────\n";
        wss << L"입력하신 `" << std::wstring(cmd.begin(), cmd.end()) << L"` (은)는 등록되지 않은 명령어입니다.\n\n";
        wss << L"관리자에게 문의하세요.";

        // WToUtf8 함수가 TelegramApi.cpp에 있으므로, TelegramApi.h를 include 해야 합니다.
        SendText(chatId, WToUtf8(wss.str()));

        // 중요: "명령어 없음"도 하나의 '처리'로 간주하여 true를 반환합니다.
        // 이렇게 해야 메인 루프에서 이 메시지를 다시 처리하지 않아 무한 루프를 방지합니다.
        return true;
    }
}

static std::string WToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &out[0], len, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

static std::string UrlEncode(const std::string& s) {
    static const char hex[] = "0123456789ABCDEF";
    std::string o;
    o.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            o.push_back((char)c);
        }
        else {
            o.push_back('%');
            o.push_back(hex[c >> 4]);
            o.push_back(hex[c & 15]);
        }
    }
    return o;
}

static std::string JsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '\"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\b': o += "\\b"; break;
        case '\f': o += "\\f"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if ('\x00' <= c && c <= '\x1f') {
                char buf[8];
                sprintf_s(buf, "\\u%04x", (int)c);
                o += buf;
            }
            else {
                o.push_back(c);
            }
        }
    }
    return o;
}