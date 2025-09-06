#pragma once
#include <string>
#include <functional>

using CmdHandler = std::function<bool(long long chatId,
    const std::string& hwid8,
    const std::string& argsUtf8)>;

void RegisterCommand(const std::string& name, CmdHandler handler);
bool DispatchCommand(long long chatId, const std::string& hwid8,
    const std::string& fullLineUtf8);

bool StartsWith(const std::string& s, const std::string& prefix);
