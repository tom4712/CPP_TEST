#pragma once
#include <string>

// 외부 IP와 국가 코드/이름을 분리해서 얻기
// 성공시 true, ipUtf8/ccUtf8/countryUtf8 채움 (cc는 대문자 2글자)
bool GetExternalIpCountryParts(std::string& ipUtf8, std::string& ccUtf8, std::string& countryUtf8);

// ISO 3166-1 alpha-2 코드 -> 국기 이모지(UTF-16)
std::wstring FlagEmojiFromCC(const std::string& cc2);
