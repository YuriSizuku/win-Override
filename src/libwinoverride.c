/**
 * redirct files to "override" folder
 *   v0.1 developed by devseed
*/

#include <windows.h>

#define WINVERSION_IMPLEMENTATION
#define WINOVERRIDE_IMPLEMENTATION
#ifdef USECOMPAT
#include "winversion_v0_1_1.h"
#include "winoverride_v0_1_3.h"
#else
#include "winversion.h"
#include "winoverride.h"
#endif

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
        winoverride_install(true);
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