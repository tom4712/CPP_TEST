#define NOMINMAX
#include "TelegramApi.h"
#include "Config.h"
#include <winhttp.h>
#include <vector>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

// ... (WToUtf8, UrlEncode 등 다른 함수들은 그대로 둠) ...

// =============================
// HTTP 요청 (핵심 수정)
// =============================
bool HttpPostForm(const std::wstring& path, const std::string& bodyUtf8, std::string& responseUtf8) {
    HINTERNET hSession = nullptr, hConnect = nullptr, hRequest = nullptr;
    BOOL bResult = FALSE;
    responseUtf8.clear();

    // <<< ADDED: 모든 토큰을 순회하며 재시도하기 위한 루프
    const size_t max_retries = GetBotTokenCount();
    if (max_retries == 0) return false; // 토큰이 없으면 실패 처리

    for (size_t attempt = 0; attempt < max_retries; ++attempt) {

        // 이전 루프에서 사용한 핸들 정리
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        hSession = WinHttpOpen(L"Telegram CppBot/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) continue;

        hConnect = WinHttpConnect(hSession, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) continue;

        // <<< CHANGED: GetCurrentBotToken()을 사용하여 현재 활성 토큰으로 fullPath 구성
        std::wstring fullPath = L"/bot" + GetCurrentBotToken() + path;

        hRequest = WinHttpOpenRequest(hConnect, L"POST", fullPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) continue;

        const std::wstring headers = L"Content-Type: application/x-www-form-urlencoded";
        bResult = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(), (LPVOID)bodyUtf8.c_str(), (DWORD)bodyUtf8.length(), (DWORD)bodyUtf8.length(), 0);
        if (!bResult) continue;

        bResult = WinHttpReceiveResponse(hRequest, NULL);
        if (!bResult) continue;

        // <<< ADDED: HTTP 상태 코드 확인 로직
        DWORD dwStatusCode = 0;
        DWORD dwSize = sizeof(dwStatusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwStatusCode, &dwSize, NULL);

        // 429 에러(Too Many Requests)인 경우, 다음 토큰으로 교체하고 재시도
        if (dwStatusCode == 429) {
            std::wcout << L"[!] Rate limit hit for token index " << (int)attempt << L". Rotating to next token..." << std::endl;
            RotateToNextBotToken();
            if (attempt < max_retries - 1) {
                continue; // 마지막 시도가 아니면 다음 루프로
            }
            // 모든 토큰을 시도했는데도 실패하면 루프 종료 후 실패 처리
        }

        // 성공했거나, 429가 아닌 다른 에러인 경우, 루프를 중단하고 결과를 처리
        // (429 외의 에러는 토큰을 바꿔도 해결되지 않을 가능성이 높음)

        DWORD dwBytesAvailable = 0;
        std::vector<char> buffer;
        while (WinHttpQueryDataAvailable(hRequest, &dwBytesAvailable) && dwBytesAvailable > 0) {
            size_t currentSize = buffer.size();
            buffer.resize(currentSize + dwBytesAvailable);
            DWORD dwRead = 0;
            WinHttpReadData(hRequest, &buffer[currentSize], dwBytesAvailable, &dwRead);
        }

        if (!buffer.empty()) {
            responseUtf8.assign(buffer.begin(), buffer.end());
        }

        // <<< ADDED: 성공적인 응답을 받으면 루프 종료
        bResult = (dwStatusCode == 200); // 200 OK일 때만 최종 성공으로 간주
        break;
    }

    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return bResult;
}


// ... (GetUpdates, SendText 등 나머지 함수들은 BOT_TOKEN을 직접 사용하지 않도록 수정) ...
// 예시: SendText 함수

bool SendText(long long chatId, const std::string& textUtf8) {
    // <<< CHANGED: BOT_TOKEN을 직접 사용하지 않고 path만 전달
    std::wstring path = L"/sendMessage";
    std::string body = "chat_id=" + std::to_string(chatId) + "&text=" + UrlEncode(textUtf8) + "&parse_mode=Markdown";

    std::string resp;
    bool ok = HttpPostForm(path, body, resp);

    std::cout << "[sendMessage] " << (ok ? resp : "HTTP error or all tokens failed") << "\\n";
    return ok && resp.find("\"ok\":true") != std::string::npos;
}

// 중요: SendTextWithButton, AnswerCallback 등 BOT_TOKEN을 직접 사용하던 모든 다른 함수들도
// 위 SendText 예시와 같이 path에서 토큰 부분을 제거하고 HttpPostForm으로 넘겨주도록 수정해야 합니다.
// 예시:
// BEFORE: std::wstring path = L"/bot" + BOT_TOKEN + L"/sendMessage";
// AFTER:  std::wstring path = L"/sendMessage";
// HttpPostForm 내부에서 GetCurrentBotToken()을 통해 토큰이 자동으로 결합됩니다.

bool SendTextWithButton(long long chatId, const std::string& textUtf8, const std::string& buttonText, const std::string& callbackData) {
    std::string markup = "{\"inline_keyboard\":[[{\"text\":\"" + buttonText + "\",\"callback_data\":\"" + callbackData + "\"}]]}";
    std::string body = "chat_id=" + std::to_string(chatId) +
        "&text=" + UrlEncode(textUtf8) + "&reply_markup=" + UrlEncode(markup);
    std::wstring path = L"/sendMessage"; // <<< CHANGED
    std::string resp; bool ok = HttpPostForm(path, body, resp);
    std::cout << "[sendMessage] " << (ok ? resp : "HTTP error") << "\\n";
    return ok && resp.find("\"ok\":true") != std::string::npos;
}

bool AnswerCallback(const std::string& callbackQueryId, const std::string& textUtf8, bool showAlert) {
    std::wstring path = L"/answerCallbackQuery"; // <<< CHANGED
    std::string body = "callback_query_id=" + UrlEncode(callbackQueryId)
        + "&text=" + UrlEncode(textUtf8)
        + "&show_alert=" + std::string(showAlert ? "true" : "false");
    std::string resp; bool ok = HttpPostForm(path, body, resp);
    std::cout << "[answerCallbackQuery] " << (ok ? resp : "HTTP error") << "\\n";
    return ok && resp.find("\"ok\":true") != std::string::npos;
}

bool EditMessageReplyMarkup(long long chatId, int messageId) {
    // <<< CHANGED: BOT_TOKEN 부분을 완전히 제거
    std::wstring path = L"/editMessageReplyMarkup";

    // reply_markup 빈 객체로 전송 → 인라인 키보드 제거
    std::string body = "chat_id=" + std::to_string(chatId)
        + "&message_id=" + std::to_string(messageId)
        + "&reply_markup=%7B%7D"; // "{}"

    std::string resp;
    bool ok = HttpPostForm(path, body, resp); // HttpPostForm이 알아서 토큰을 붙여줌

    std::cout << "[editMessageReplyMarkup] " << (ok ? resp : "HTTP error") << "\n";
    return ok && resp.find("\"ok\":true") != std::string::npos;
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