#pragma once
#include <string>
#include <vector>

// <<< CHANGED: ���� const std::wstring BOT_TOKEN; ���� ����

// �� ��ū ���� �Լ�
std::wstring GetCurrentBotToken();     // <<< ADDED: ���� Ȱ��ȭ�� ��ū�� �������� �Լ�
void RotateToNextBotToken();           // <<< ADDED: ���� ��ū���� ��ȯ��Ű�� �Լ�
size_t GetBotTokenCount();             // <<< ADDED: ������ ��ü ��ū�� ������ ��ȯ�ϴ� �Լ�

// ä�� ID�� �״�� ����
const long long CHAT_ID = -1002957485456;