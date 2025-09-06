#pragma once
#include <string>

// 고유번호: MachineGuid 기반 8자리(대문자). 실패 시 C: 볼륨 시리얼 8자리, 그마저 실패면 "UNKNOWN"
std::wstring GetStableMachineId8();

// 업타임 "Xd Yh Zm" 또는 "3h 20m" 형식
std::wstring GetUptimePretty();
