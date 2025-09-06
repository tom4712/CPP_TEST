#pragma once
#include <string>
#include <windows.h>

std::string WToUtf8(const std::wstring& w);
std::string UrlEncode(const std::string& s);
std::string JsonEscape(const std::string& s);

bool HttpPostForm(const std::wstring& path, const std::string& body, std::string& out);

bool SendText(long long chatId, const std::string& textUtf8);
bool SendTextWithButton(long long chatId, const std::string& textUtf8,
    const std::string& btnTextUtf8, const std::string& callbackDataUtf8);

bool AnswerCallback(const std::string& callbackQueryId, const std::string& textUtf8, bool showAlert = false);
bool EditMessageReplyMarkup(long long chatId, int messageId); // 해당 메시지의 인라인 키보드 제거
