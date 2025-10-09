#include <locale.h>
#include <windows.h>

#define WINVERSION_IMPLEMENTATION
#define WINOVERRIDE_IMPLEMENTATION
#include "winversion.h"
#include "winoverride.h"

EXPORT void dummy()
{

}

static void show_info()
{
    LOGi("winoverride v%s, developed by devseed\n", WINOVERRIDE_VERSION);
    DWORD winver = GetVersion();
    DWORD winver_major = (DWORD)(LOBYTE(LOWORD(winver)));
    DWORD winver_minor = (DWORD)(HIBYTE(LOWORD(winver)));
    LOGi("version NT=%lu.%lu\n", winver_major, winver_minor);
    #if defined(_MSC_VER)
    LOGi("compiler MSVC=%d\n", _MSC_VER)
    #elif defined(__GNUC__)
    LOGi("compiler GNUC=%d.%d\n", __GNUC__, __GNUC_MINOR__);
    #elif defined(__TINYC__)
    LOGi("compiler TCC\n");
    #endif
}

static bool prepare_console()
{
    FILE *fp = fopen("DEBUG_CONSOLE", "rb");
    if (!fp) return false;
    fclose(fp);
    
    // for wprintf 
    UINT codepage = GetACP();
    if (codepage==936)
    {
        system("chcp 936");
        setlocale(LC_ALL, "chs");
    }
    else if (codepage==932)
    {
        system("chcp 932");
        setlocale(LC_ALL, "Japanese");
    }
    
    // attach console
    AllocConsole();
    SetConsoleTitleA("winoverride v" WINOVERRIDE_VERSION ", developed by devseed");
    freopen("CONOUT$", "w", stdout);
    system("pause");
    
    return true;
}

// in win11, build from visual studio might failed, need to copy ucrtbased.dll
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        prepare_console();
        show_info();
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