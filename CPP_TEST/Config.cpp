#include "Config.h"
#include <vector>
#include <string>
#include <atomic> // <<< ADDED: 스레드 안전성을 위해 추가

// <<< REMOVED: const std::wstring BOT_TOKEN = L"..."; 라인 제거

// <<< ADDED: 여러 개의 봇 토큰을 관리하는 벡터
// 중요: 여기에 사용할 봇 토큰들을 모두 입력하세요.
static const std::vector<std::wstring> g_botTokens = {
    L"8494613693:AAG1cNGBuhuja8Pz5zt5dEcwmgg4PXEZ-y8",
    L"8151800484:AAHbX1uOt4dZ9xmoODsghAIQZkPCDIFz7P8",
    L"8407614017:AAGS6BspOElBRpT9WqpteHxuSMqF12E_iDs",
    L"8440595500:AAEeUyDCdtGHxZafOQ562GioO4WFHamJAh8"
    // 필요한 만큼 더 추가할 수 있습니다.
};

// <<< ADDED: 현재 사용 중인 토큰의 인덱스를 추적하는 변수 (스레드 안전)
static std::atomic<size_t> g_currentTokenIndex = 0;

// --- 아래 함수들 전체 추가 ---

// <<< ADDED: 현재 활성화된 토큰을 반환
std::wstring GetCurrentBotToken() {
    if (g_botTokens.empty()) {
        return L"";
    }
    // 현재 인덱스에 해당하는 토큰을 반환
    return g_botTokens[g_currentTokenIndex.load(std::memory_order_relaxed)];
}

// <<< ADDED: 다음 토큰으로 인덱스를 순환
void RotateToNextBotToken() {
    if (g_botTokens.empty()) {
        return;
    }
    // 현재 인덱스를 1 증가시키고, 토큰 개수로 나눈 나머지를 취해 순환시킴
    g_currentTokenIndex.store((g_currentTokenIndex.load(std::memory_order_relaxed) + 1) % g_botTokens.size(), std::memory_order_relaxed);
}

// <<< ADDED: 설정된 전체 토큰의 개수를 반환
size_t GetBotTokenCount() {
    return g_botTokens.size();
}