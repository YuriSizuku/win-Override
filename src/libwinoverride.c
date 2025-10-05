/**
 * redirct files to "override" folder
 *   v0.1 developed by devseed
*/

#include <windows.h>

#define WINVERSION_IMPLEMENT
#define WINOVERRIDE_IMPLEMENT
#ifdef USECOMPAT
#include "winversion_v0_1_1.h"
#include "winoverride_v0_1.h"
#else
#include "winversion.h"
#include "winoverride.h"
#endif

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        winversion_install();
        winoverride_install();
        winoverride_banner();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        winoverride_uninstall();
        break;
    }
    return TRUE;
}