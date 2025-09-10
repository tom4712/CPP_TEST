#include "Config.h"
#include <vector>
#include <string>
#include <atomic> // <<< ADDED: ������ �������� ���� �߰�

// <<< REMOVED: const std::wstring BOT_TOKEN = L"..."; ���� ����

// <<< ADDED: ���� ���� �� ��ū�� �����ϴ� ����
// �߿�: ���⿡ ����� �� ��ū���� ��� �Է��ϼ���.
static const std::vector<std::wstring> g_botTokens = {
    L"8494613693:AAG1cNGBuhuja8Pz5zt5dEcwmgg4PXEZ-y8",
    L"8151800484:AAHbX1uOt4dZ9xmoODsghAIQZkPCDIFz7P8",
    L"8407614017:AAGS6BspOElBRpT9WqpteHxuSMqF12E_iDs",
    L"8440595500:AAEeUyDCdtGHxZafOQ562GioO4WFHamJAh8"
    // �ʿ��� ��ŭ �� �߰��� �� �ֽ��ϴ�.
};

// <<< ADDED: ���� ��� ���� ��ū�� �ε����� �����ϴ� ���� (������ ����)
static std::atomic<size_t> g_currentTokenIndex = 0;

// --- �Ʒ� �Լ��� ��ü �߰� ---

// <<< ADDED: ���� Ȱ��ȭ�� ��ū�� ��ȯ
std::wstring GetCurrentBotToken() {
    if (g_botTokens.empty()) {
        return L"";
    }
    // ���� �ε����� �ش��ϴ� ��ū�� ��ȯ
    return g_botTokens[g_currentTokenIndex.load(std::memory_order_relaxed)];
}

// <<< ADDED: ���� ��ū���� �ε����� ��ȯ
void RotateToNextBotToken() {
    if (g_botTokens.empty()) {
        return;
    }
    // ���� �ε����� 1 ������Ű��, ��ū ������ ���� �������� ���� ��ȯ��Ŵ
    g_currentTokenIndex.store((g_currentTokenIndex.load(std::memory_order_relaxed) + 1) % g_botTokens.size(), std::memory_order_relaxed);
}

// <<< ADDED: ������ ��ü ��ū�� ������ ��ȯ
size_t GetBotTokenCount() {
    return g_botTokens.size();
}