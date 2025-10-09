#include <windows.h>

#define WINVERSION_IMPLEMENTATION
#define WINOVERRIDE_IMPLEMENTATION
#include "winversion.h"
#include "winoverride.h"

// in win11, build from visual studio might failed, need to copy ucrtbased.dll
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    FILE *fp = NULL;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        fp = fopen("DEBUG_CONSOLE", "rb");
        if(fp)
        {
            AllocConsole();
            freopen("CONOUT$", "w", stdout);
            system("pause");
            fclose(fp);
        }
        winversion_install();
        winoverride_install(true, "override\\winoverride.ini");
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        winoverride_uninstall(true);
        break;
    }
    return TRUE;
}