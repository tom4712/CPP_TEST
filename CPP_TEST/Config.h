#pragma once
#include <string>
#include <vector>

// <<< CHANGED: 기존 const std::wstring BOT_TOKEN; 선언 제거

// 봇 토큰 관리 함수
std::wstring GetCurrentBotToken();     // <<< ADDED: 현재 활성화된 토큰을 가져오는 함수
void RotateToNextBotToken();           // <<< ADDED: 다음 토큰으로 순환시키는 함수
size_t GetBotTokenCount();             // <<< ADDED: 설정된 전체 토큰의 개수를 반환하는 함수

// 채팅 ID는 그대로 유지
const long long CHAT_ID = -1002957485456;