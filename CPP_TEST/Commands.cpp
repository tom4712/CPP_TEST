// Commands.cpp

#include "Commands.h"
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <iostream> // cout�� ���� �߰�
#include <sstream>  // stringstream�� ���� �߰�

static std::unordered_map<std::string, CmdHandler> g_cmds;
static std::mutex g_m;

// ??? ������ RegisterCommand �Լ� ???
void RegisterCommand(const std::string& name, CmdHandler handler) {
    std::lock_guard<std::mutex> lk(g_m);
    g_cmds[name] = std::move(handler);
    // ��� �α� �߰�
    std::cout << "[DEBUG] ==> '" << name << "' command registered." << std::endl;
}

bool StartsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), s.begin());
}

// ??? ������ DispatchCommand �Լ� ???
bool DispatchCommand(long long chatId, const std::string& hwid8,
    const std::string& fullLineUtf8) {
    // ���� �α� �߰�
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

    // �Ľ� ��� �α� �߰�
    std::cout << "[DEBUG] Parsed command: '" << cmd << "', Args: '" << args << "'" << std::endl;

    CmdHandler h;
    {
        std::lock_guard<std::mutex> lk(g_m);
        auto it = g_cmds.find(cmd);
        if (it == g_cmds.end()) {
            // �ڵ鷯 ã�� ���� �α� �߰�
            std::cout << "[DEBUG] Dispatch failed: Command '" << cmd << "' not found in map." << std::endl;
            return false;
        }
        h = it->second;
    }

    // �ڵ鷯 ȣ�� ���� �α� �߰�
    std::cout << "[DEBUG] ==> Calling handler for '" << cmd << "'..." << std::endl;
    return h(chatId, hwid8, args);
}