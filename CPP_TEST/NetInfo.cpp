#include "NetInfo.h"
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <cctype>

#pragma comment(lib, "winhttp.lib")

static std::string PickJsonString(const std::string& js, const char* key) {
    std::string pat = std::string("\"") + key + "\":";
    size_t p = js.find(pat);
    if (p == std::string::npos) return {};
    p += pat.size();
    while (p < js.size() && (js[p] == ' ')) ++p;
    if (p >= js.size() || js[p] != '"') return {};
    ++p;
    size_t q = js.find('"', p);
    if (q == std::string::npos) return {};
    return js.substr(p, q - p);
}

bool GetExternalIpCountryParts(std::string& ipUtf8, std::string& ccUtf8, std::string& countryUtf8) {
    HINTERNET S = WinHttpOpen(L"CppBot/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!S) return false;
    HINTERNET C = WinHttpConnect(S, L"ipapi.co", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!C) { WinHttpCloseHandle(S); return false; }
    HINTERNET R = WinHttpOpenRequest(C, L"GET", L"/json", nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!R) { WinHttpCloseHandle(C); WinHttpCloseHandle(S); return false; }

    bool ok = WinHttpSendRequest(R, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        && WinHttpReceiveResponse(R, nullptr);
    std::string body;
    if (ok) {
        DWORD rd = 0;
        do {
            DWORD sz = 0;
            if (!WinHttpQueryDataAvailable(R, &sz) || sz == 0) break;
            std::string chunk(sz, '\0');
            if (!WinHttpReadData(R, &chunk[0], sz, &rd)) break;
            body.append(chunk.data(), rd);
        } while (rd > 0);
    }
    WinHttpCloseHandle(R); WinHttpCloseHandle(C); WinHttpCloseHandle(S);
    if (!ok || body.empty()) return false;

    auto ip = PickJsonString(body, "ip");
    auto cc = PickJsonString(body, "country_code");
    auto cn = PickJsonString(body, "country_name");

    if (ip.empty()) return false;
    // 대문자 2글자로 정규화
    if (cc.size() == 2) { cc[0] = (char)std::toupper((unsigned char)cc[0]); cc[1] = (char)std::toupper((unsigned char)cc[1]); }

    ipUtf8 = ip;
    ccUtf8 = cc;
    countryUtf8 = cn;
    return true;
}

// UTF-32 코드포인트를 UTF-16로 append
static void AppendUtf32(std::wstring& out, uint32_t cp) {
    if (cp <= 0xFFFF) {
        out.push_back((wchar_t)cp);
    }
    else {
        cp -= 0x10000;
        wchar_t hi = (wchar_t)(0xD800 + (cp >> 10));
        wchar_t lo = (wchar_t)(0xDC00 + (cp & 0x3FF));
        out.push_back(hi); out.push_back(lo);
    }
}

std::wstring FlagEmojiFromCC(const std::string& cc2) {
    if (cc2.size() != 2) return L"";
    char a = (char)std::toupper((unsigned char)cc2[0]);
    char b = (char)std::toupper((unsigned char)cc2[1]);
    if (a < 'A' || a > 'Z' || b < 'A' || b > 'Z') return L"";

    uint32_t base = 0x1F1E6; // REGIONAL INDICATOR SYMBOL LETTER A
    uint32_t cp1 = base + (a - 'A');
    uint32_t cp2 = base + (b - 'A');
    std::wstring w;
    AppendUtf32(w, cp1);
    AppendUtf32(w, cp2);
    return w;
}
