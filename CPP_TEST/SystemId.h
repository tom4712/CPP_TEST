#pragma once
#include <string>

// ������ȣ: MachineGuid ��� 8�ڸ�(�빮��). ���� �� C: ���� �ø��� 8�ڸ�, �׸��� ���и� "UNKNOWN"
std::wstring GetStableMachineId8();

// ��Ÿ�� "Xd Yh Zm" �Ǵ� "3h 20m" ����
std::wstring GetUptimePretty();
