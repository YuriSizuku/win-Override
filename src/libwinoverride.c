/**
 * redirct files to "override" folder
 *   v0.1 developed by devseed
*/

#include <windows.h>

#if defined(_MSC_VER) || defined(__TINYC__)
#pragma warning(push)
#pragma warning(disable: 4005)
#include <windows.h>
#include <winternl.h>
#pragma warning(pop)
#else
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#endif // _MSC_VER
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#endif

#define MINHOOK_IMPLEMENTATION
#define MINHOOK_STATIC
#ifdef USECOMPAT
#include "winversion_v0_1_1.h"
#include "stb_minhook_v1_3_3_2.h"
#else
#include "winversion.h"
#include "stb_minhook.h"
#endif

#define REDIRECT_DIRW L"override"
#define DEFINE_HOOK(name) \
    t##name name##_org = NULL; \
    void *name##_old;

#define BIND_HOOK(name) \
    MH_CreateHook(name##_old, (LPVOID)(name##_hook), (LPVOID*)(&name##_org));\
    LOGi("BIND_HOOK " #name " %p -> %p\n", name##_old, name##_hook);\
    MH_EnableHook(name##_old)

#define UNBIND_HOOK(name) \
    if(name##_old) {\
        MH_DisableHook(name##_old); \
        LOGi("UNBIND_HOOK " #name " %p\n", name##_old); \
    }

typedef NTSTATUS (NTAPI *tNtCreateFile)(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN OPTIONAL PLARGE_INTEGER AllocationSize,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN OPTIONAL PVOID EaBuffer,
    IN ULONG EaLength);

DEFINE_HOOK(NtCreateFile);

size_t relpathw(const wchar_t *srcpath, const wchar_t *basepath, wchar_t *relpath)
{
    relpath[0] = L'\0';
    if (wcsncmp(srcpath, L"\\Device", 7)==0) return 0;
    if (wcsncmp(srcpath, L"\\??\\", 4)==0) // nt global path
    {

        if (wcsstr(srcpath + 4, basepath))
        {
            wcscpy(relpath, srcpath + 4 + wcslen(basepath));
        }
    }
    else
    {
        wcscpy(relpath, srcpath);
    }

    for (int i = 0; relpath[i]; i++)
    {
        if (relpath[i] == L'/') relpath[i] = L'\\';
    }

    int offset = 0;
    if(relpath[0]==L'\\') offset=1;
    else if(relpath[0]==L'.' && relpath[1]==L'\\') offset=2;
    if(offset > 0) wcsncpy(relpath, relpath+offset, wcslen(relpath)+1-offset);

    return wcslen(relpath);
} 

static NTSTATUS NTAPI NtCreateFile_hook( 
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN OPTIONAL PLARGE_INTEGER AllocationSize,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN OPTIONAL PVOID EaBuffer,
    IN ULONG EaLength) // mainly for file
{
    wchar_t cwd[MAX_PATH], rel[MAX_PATH], target[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, cwd);
    tNtCreateFile pfn = NtCreateFile_org;

    NTSTATUS status = -1;
    if(CreateOptions & FILE_DIRECTORY_FILE) // if dir
    {
        status = pfn(FileHandle, DesiredAccess, 
            ObjectAttributes, IoStatusBlock, AllocationSize,
            FileAttributes, ShareAccess, CreateDisposition, 
            CreateOptions, EaBuffer, EaLength);
    }
    else 
    {
        if((DesiredAccess & FILE_GENERIC_READ)||
        (DesiredAccess & FILE_GENERIC_EXECUTE))
        {
            relpathw(ObjectAttributes->ObjectName->Buffer, cwd, rel);
            if(!rel[0])
            {
                status = pfn(FileHandle, DesiredAccess, 
                    ObjectAttributes, IoStatusBlock, AllocationSize,
                    FileAttributes, ShareAccess, CreateDisposition, 
                    CreateOptions, EaBuffer, EaLength);
            }
            else
            {
                PUNICODE_STRING pustrorg = ObjectAttributes->ObjectName; 
                wcscpy(target, L"\\??\\");
                wcscat(target, cwd);
                wcscat(target, L"\\" REDIRECT_DIRW L"\\");
                wcscat(target, rel);
                UNICODE_STRING ustr = { .Buffer = target, .Length = (USHORT)wcslen(target) * 2, .MaximumLength = sizeof(target) };
                
                ObjectAttributes->ObjectName = &ustr;
                status = pfn(FileHandle, DesiredAccess, 
                    ObjectAttributes, IoStatusBlock, AllocationSize,
                    FileAttributes, ShareAccess, CreateDisposition, 
                    CreateOptions, EaBuffer, EaLength);
                ObjectAttributes->ObjectName = pustrorg;

                if(NT_SUCCESS(status))
                {
                    LOGLi(L"REDIRECT %ls\n", rel);
                }
                else
                {
                    status = pfn(FileHandle, DesiredAccess, 
                        ObjectAttributes, IoStatusBlock, AllocationSize,
                        FileAttributes, ShareAccess, CreateDisposition, 
                        CreateOptions, EaBuffer, EaLength);
                    LOGLi(L"LOAD %ls %ld\n", rel, status);
                }
            }
        }
        else
        {
            status = pfn(FileHandle, DesiredAccess,
                ObjectAttributes, IoStatusBlock, AllocationSize,
                FileAttributes, ShareAccess, CreateDisposition,
                CreateOptions, EaBuffer, EaLength);
        }
    }
    return status;
}

static void print_info()
{
    printf("libwinoverride v0.1, developed by devseed\n");
    
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

static void winoverride_init()
{
    FILE *fp = fopen("DEBUG_CONSOLE", "rb");
    if(fp)
    {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        system("pause");
        fclose(fp);
    }
    print_info();

    MH_STATUS status = MH_Initialize();
    if(status != MH_OK)
    {
        LOGe("MH_Initialize failed with %s\n", MH_StatusToString(status));
        return;
    }
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    NtCreateFile_old = GetProcAddress(ntdll, "NtCreateFile");
    BIND_HOOK(NtCreateFile);
}

static void winoverride_uninit()
{

    MH_STATUS status = MH_Uninitialize();
    if(status != MH_OK)
    {
        LOGe("MH_Initialize failed with %s\n", MH_StatusToString(status));
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        winversion_init();
        winoverride_init();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        winoverride_uninit();
        break;
    }
    return TRUE;
}