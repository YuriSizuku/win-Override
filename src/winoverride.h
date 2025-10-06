/**
 * single header file file repatch tool
 *   v0.1 developed by devseed
 * 
 * macros:
 *    WINOVERRIDE_IMPLEMENTATION, include implements of each function
 *    WINOVERRIDE_SHARED, make function export
 *    WINOVERRIDE_STATIC, make function static
 *    WINOVERRIDE_REDIRECTDIRW, redirect dir
*/

#ifndef _WINOVERRIDE_H
#define _WINOVERRIDE_H

#ifdef __cplusplus
extern "C" {
#endif

#define WINOVERRIDE_VERSION "0.1"

#ifdef USECOMPAT
#include "commdef_v0_1_1.h"
#else
#include "commdef.h"
#endif // USECOMPAT

// define specific macro
#ifndef WINOVERRIDE_API
#ifdef WINOVERRIDE_STATIC
#define WINOVERRIDE_API_DEF static
#else
#define WINOVERRIDE_API_DEF extern
#endif // WINOVERRIDE_STATIC
#ifdef WINOVERRIDE_SHARED
#define WINOVERRIDE_API_EXPORT EXPORT
#else  
#define WINOVERRIDE_API_EXPORT
#endif // WINOVERRIDE_SHARED
#define WINOVERRIDE_API WINOVERRIDE_API_DEF WINOVERRIDE_API_EXPORT
#endif // WINOVERRIDE_API

WINOVERRIDE_API
size_t winoverride_relpathw(const wchar_t *srcpath, const wchar_t *basepath, wchar_t *relpath);

WINOVERRIDE_API
void winoverride_banner();

WINOVERRIDE_API
void winoverride_install();

WINOVERRIDE_API
void winoverride_uninstall();

#ifdef WINOVERRIDE_IMPLEMENTATION
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

#if defined (__TINYC__)
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;
#define FILE_DIRECTORY_FILE  0x00000001
#define FILE_SUPERSEDED 0x00000000
#define FILE_OPENED 0x00000001
#define FILE_CREATED 0x00000002
#define FILE_OVERWRITTEN 0x00000003
#define FILE_EXISTS 0x00000004
#define FILE_DOES_NOT_EXIST 0x00000005
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define MINHOOK_IMPLEMENTATION
#define MINHOOK_STATIC
#ifdef USECOMPAT
#include "commdef_v0_1_1.h"
#include "stb_minhook_v1_3_3_2.h"
#else
#include "commdef.h"
#include "stb_minhook.h"
#endif

#ifndef WINOVERRIDE_REDIRECTDIRW
#define WINOVERRIDE_REDIRECTDIRW L"override"
#endif
#define WINOVERRIDE_DEFINEHOOK(name) \
    t##name name##_org = NULL; \
    void *name##_old;

#define WINOVERRIDE_BINDHOOK(name) \
    MH_CreateHook(name##_old, (LPVOID)(name##_hook), (LPVOID*)(&name##_org));\
    LOGi("WINOVERRIDE_BINDHOOK " #name " %p -> %p\n", name##_old, name##_hook);\
    MH_EnableHook(name##_old)

#define WINOVERRIDE_UNBINDHOOK(name) \
    if(name##_old) {\
        MH_DisableHook(name##_old); \
        LOGi("UNWINOVERRIDE_BINDHOOK " #name " %p\n", name##_old); \
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

WINOVERRIDE_DEFINEHOOK(NtCreateFile);

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
            winoverride_relpathw(ObjectAttributes->ObjectName->Buffer, cwd, rel);
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
                wcscat(target, L"\\" WINOVERRIDE_REDIRECTDIRW L"\\");
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

size_t winoverride_relpathw(const wchar_t *srcpath, const wchar_t *basepath, wchar_t *relpath)
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

void winoverride_banner()
{
    LOGi("winoverride v0.1, developed by devseed\n");
    
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

void winoverride_install()
{
    FILE *fp = fopen("DEBUG_CONSOLE", "rb");
    if(fp)
    {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        system("pause");
        fclose(fp);
    }

    MH_STATUS status = MH_Initialize();
    if(status != MH_OK)
    {
        LOGe("MH_Initialize failed with %s\n", MH_StatusToString(status));
    }
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    NtCreateFile_old = GetProcAddress(ntdll, "NtCreateFile");
    WINOVERRIDE_BINDHOOK(NtCreateFile);
}

void winoverride_uninstall()
{

    MH_STATUS status = MH_Uninitialize();
    if(status != MH_OK)
    {
        LOGe("MH_Initialize failed with %s\n", MH_StatusToString(status));
    }
}
#endif
#ifdef __cplusplus
}
#endif
#endif