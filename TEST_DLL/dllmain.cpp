// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include <fstream> // ❗ 파일 입출력을 위해 이 헤더를 추가합니다.

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // --- 🚀 이 DLL이 다른 프로세스에 성공적으로 주입되었을 때 이 코드가 실행됩니다 ---
    {
        // C 드라이브 루트에 성공했다는 증거로 파일을 생성합니다.
        std::ofstream outfile("C:\\dll_success.txt");
        if (outfile.is_open())
        {
            outfile << "DLL injection and execution successful!";
            outfile.close();
        }
    }
    break;
    // --------------------------------------------------------------------------

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE; // 성공적으로 로드되었음을 알리기 위해 TRUE를 반환해야 합니다.
}