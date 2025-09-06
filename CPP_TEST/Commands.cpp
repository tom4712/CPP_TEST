// Commands.cpp

#include "Commands.h"
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
    // 수신 로그 추가
    std::cout << "[DEBUG] Received message: \"" << fullLineUtf8 << "\"" << std::endl;

    const std::string head = "/" + hwid8 + " ";
    if (!StartsWith(fullLineUtf8, head)) {
        std::cout << "[DEBUG] Dispatch failed: Prefix mismatch." << std::endl;
        return false;
    }

    size_t p = head.size();
    size_t q = fullLineUtf8.find(' ', p);
    std::string cmd = (q == std::string::npos) ? fullLineUtf8.substr(p)
        : fullLineUtf8.substr(p, q - p);
    std::string args = (q == std::string::npos) ? std::string()
        : fullLineUtf8.substr(q + 1);

    // 파싱 결과 로그 추가
    std::cout << "[DEBUG] Parsed command: '" << cmd << "', Args: '" << args << "'" << std::endl;

    CmdHandler h;
    {
        std::lock_guard<std::mutex> lk(g_m);
        auto it = g_cmds.find(cmd);
        if (it == g_cmds.end()) {
            // 핸들러 찾기 실패 로그 추가
            std::cout << "[DEBUG] Dispatch failed: Command '" << cmd << "' not found in map." << std::endl;
            return false;
        }
        h = it->second;
    }

    // 핸들러 호출 성공 로그 추가
    std::cout << "[DEBUG] ==> Calling handler for '" << cmd << "'..." << std::endl;
    return h(chatId, hwid8, args);
}