#define NOMINMAX
#include "TelegramApi.h"
#include "Config.h"
#include <winhttp.h>
#include <vector>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

std::string WToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &out[0], len, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}
std::string UrlEncode(const std::string& s) {
    static const char hex[] = "0123456789ABCDEF";
    std::string o; o.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')
            || c == '-' || c == '_' || c == '.' || c == '~') o.push_back((char)c);
        else { o.push_back('%'); o.push_back(hex[c >> 4]); o.push_back(hex[c & 15]); }
    }
    return o;
}
std::string JsonEscape(const std::string& s) {
    std::string o; o.reserve(s.size() * 2);
    for (unsigned char c : s) {
        if (c == '"') o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else o.push_back((char)c);
    }
    return o;
}

bool HttpPostForm(const std::wstring& path, const std::string& body, std::string& out) {
    HINTERNET S = WinHttpOpen(L"CppBot/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!S) return false;
    HINTERNET C = WinHttpConnect(S, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!C) { WinHttpCloseHandle(S); return false; }
    HINTERNET R = WinHttpOpenRequest(C, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!R) { WinHttpCloseHandle(C); WinHttpCloseHandle(S); return false; }

    std::wstring hdr = L"Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n";
    BOOL ok = WinHttpSendRequest(R, hdr.c_str(), (DWORD)-1, (LPVOID)body.data(),
        (DWORD)body.size(), (DWORD)body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(R, nullptr);

    bool ret = false;
    if (ok) {
        DWORD rd = 0;
        do {
            DWORD sz = 0;
            if (!WinHttpQueryDataAvailable(R, &sz) || sz == 0) break;
            std::vector<char> buf(sz + 1, 0);
            if (!WinHttpReadData(R, buf.data(), sz, &rd)) break;
            out.append(buf.data(), rd);
        } while (rd > 0);
        ret = true;
    }
    WinHttpCloseHandle(R); WinHttpCloseHandle(C); WinHttpCloseHandle(S);
    return ret;
}

bool SendText(long long chatId, const std::string& textUtf8) {
    // text 파라미터 뒤에 parse_mode=Markdown 파라미터를 추가합니다.
    std::string body = "chat_id=" + std::to_string(chatId) + "&text=" + UrlEncode(textUtf8) + "&parse_mode=Markdown";
    std::wstring path = L"/bot" + BOT_TOKEN + L"/sendMessage";
    std::string resp; bool ok = HttpPostForm(path, body, resp);
    std::cout << "[sendMessage] " << (ok ? resp : "HTTP error") << "\n";
    return ok && resp.find("\"ok\":true") != std::string::npos;
}
bool SendTextWithButton(long long chatId, const std::string& textUtf8,
    const std::string& btnTextUtf8, const std::string& callbackDataUtf8) {
    std::string markup = "{\"inline_keyboard\":[[{\"text\":\"" + JsonEscape(btnTextUtf8) +
        "\",\"callback_data\":\"" + JsonEscape(callbackDataUtf8) + "\"}]]}";
    std::string body = "chat_id=" + std::to_string(chatId) +
        "&text=" + UrlEncode(textUtf8) + "&reply_markup=" + UrlEncode(markup);
    std::wstring path = L"/bot" + BOT_TOKEN + L"/sendMessage";
    std::string resp; bool ok = HttpPostForm(path, body, resp);
    std::cout << "[sendMessage] " << (ok ? resp : "HTTP error") << "\n";
    return ok && resp.find("\"ok\":true") != std::string::npos;
}

bool AnswerCallback(const std::string& callbackQueryId, const std::string& textUtf8, bool showAlert) {
    std::wstring path = L"/bot" + BOT_TOKEN + L"/answerCallbackQuery";
    std::string body = "callback_query_id=" + UrlEncode(callbackQueryId)
        + "&text=" + UrlEncode(textUtf8)
        + "&show_alert=" + std::string(showAlert ? "true" : "false");
    std::string resp; bool ok = HttpPostForm(path, body, resp);
    std::cout << "[answerCallbackQuery] " << (ok ? resp : "HTTP error") << "\n";
    return ok && resp.find("\"ok\":true") != std::string::npos;
}

bool EditMessageReplyMarkup(long long chatId, int messageId) {
    std::wstring path = L"/bot" + BOT_TOKEN + L"/editMessageReplyMarkup";
    // reply_markup 빈 객체로 전송 → 인라인 키보드 제거
    std::string body = "chat_id=" + std::to_string(chatId)
        + "&message_id=" + std::to_string(messageId)
        + "&reply_markup=%7B%7D"; // "{}"
    std::string resp; bool ok = HttpPostForm(path, body, resp);
    std::cout << "[editMessageReplyMarkup] " << (ok ? resp : "HTTP error") << "\n";
    return ok && resp.find("\"ok\":true") != std::string::npos;
}
