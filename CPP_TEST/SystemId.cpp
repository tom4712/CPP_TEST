// SystemId.cpp
#include "SystemId.h"
#include <windows.h>
#include <vector>
#include <string>
#include <cwctype>   // towupper

#pragma comment(lib, "advapi32.lib")

static std::wstring ReadRegString(HKEY root, const wchar_t* subkey, const wchar_t* name) {
    HKEY h{};
    if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE, &h) != ERROR_SUCCESS) return L"";
    wchar_t buf[256]; DWORD cb = sizeof(buf); DWORD type = 0;
    LONG r = RegGetValueW(h, nullptr, name, RRF_RT_REG_SZ, &type, buf, &cb);
    RegCloseKey(h);
    if (r != ERROR_SUCCESS) return L"";
    return buf;
}

static std::wstring GetCDriveSerial8() {
    DWORD serial = 0;
    if (GetVolumeInformationW(L"C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        wchar_t w[16]; swprintf(w, 16, L"%08X", serial);
        return w;
    }
    return L"";
}

// 고유번호: MachineGuid에서 16진 문자만 추출해 대문자 8자리 사용
// 실패 시 C: 볼륨 시리얼 8자리, 그래도 없으면 "UNKNOWN"
std::wstring GetStableMachineId8() {
    // 1) MachineGuid
    auto mg = ReadRegString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    if (!mg.empty()) {
        std::wstring hex; hex.reserve(32);
        for (wchar_t c : mg) {
            const bool is_hex =
                (c >= L'0' && c <= L'9') ||
                (c >= L'a' && c <= L'f') ||
                (c >= L'A' && c <= L'F');
            if (is_hex) {
                hex.push_back((wchar_t)::towupper(c));  // ← wide 대문자화
                if (hex.size() == 8) break;
            }
        }
        if (hex.size() == 8) return hex;
    }

    // 2) C: 볼륨 시리얼
    auto s = GetCDriveSerial8();
    if (!s.empty()) return s;

    // 3) 실패
    return L"UNKNOWN";
}

// 업타임: "Xd Yh", "Xh Ym", 또는 "Xm"
std::wstring GetUptimePretty() {
    ULONGLONG ms = GetTickCount64();
    ULONGLONG sec = ms / 1000;
    ULONGLONG d = sec / 86400;
    ULONGLONG h = (sec % 86400) / 3600;
    ULONGLONG m = (sec % 3600) / 60;

    wchar_t w[64];
    if (d) swprintf(w, 64, L"%llud %lluh", d, h);
    else if (h) swprintf(w, 64, L"%lluh %llum", h, m);
    else swprintf(w, 64, L"%llum", m);
    return w;
}
