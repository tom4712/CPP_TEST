#pragma once
#include <string>

// �ܺ� IP�� ���� �ڵ�/�̸��� �и��ؼ� ���
// ������ true, ipUtf8/ccUtf8/countryUtf8 ä�� (cc�� �빮�� 2����)
bool GetExternalIpCountryParts(std::string& ipUtf8, std::string& ccUtf8, std::string& countryUtf8);

// ISO 3166-1 alpha-2 �ڵ� -> ���� �̸���(UTF-16)
std::wstring FlagEmojiFromCC(const std::string& cc2);
