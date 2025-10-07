/**
 * single header file file repatch tool
 *   v0.1.3 developed by devseed
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

#define WINOVERRIDE_VERSION "0.1.3"

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

#if defined (_MSC_VER) || defined (__TINYC__)
typedef struct _FILE_STAT_INFORMATION {
    LARGE_INTEGER FileId;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         FileAttributes;
    ULONG         ReparseTag;
    ULONG         NumberOfLinks;
    ACCESS_MASK   EffectiveAccess;
} FILE_STAT_INFORMATION, * PFILE_STAT_INFORMATION;

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, * PFILE_POSITION_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef struct _FILE_INTERNAL_INFORMATION {
    LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, * PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION {
    ULONG EaSize;
} FILE_EA_INFORMATION, * PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION {
    ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, * PFILE_ACCESS_INFORMATION;

typedef struct _FILE_MODE_INFORMATION {
    ULONG Mode;
} FILE_MODE_INFORMATION, * PFILE_MODE_INFORMATION;

typedef struct _FILE_ALIGNMENT_INFORMATION {
    ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION, * PFILE_ALIGNMENT_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    WCHAR         FileName[1];
}FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, * PFILE_NAME_INFORMATION;

typedef struct _FILE_ALL_INFORMATION {
    FILE_BASIC_INFORMATION     BasicInformation;
    FILE_STANDARD_INFORMATION  StandardInformation;
    FILE_INTERNAL_INFORMATION  InternalInformation;
    FILE_EA_INFORMATION        EaInformation;
    FILE_ACCESS_INFORMATION    AccessInformation;
    FILE_POSITION_INFORMATION  PositionInformation;
    FILE_MODE_INFORMATION      ModeInformation;
    FILE_ALIGNMENT_INFORMATION AlignmentInformation;
    FILE_NAME_INFORMATION      NameInformation;
} FILE_ALL_INFORMATION, * PFILE_ALL_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    WCHAR         FileName[1];
} FILE_FULL_DIR_INFORMATION, * PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    CCHAR         ShortNameLength;
    WCHAR         ShortName[12];
    WCHAR         FileName[1];
} FILE_BOTH_DIR_INFORMATION, * PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    CCHAR         ShortNameLength;
    WCHAR         ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR         FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    LARGE_INTEGER FileId;
    WCHAR         FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, * PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, * PFILE_NETWORK_OPEN_INFORMATION;

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
    void *name##_old; \
    HANDLE name##_mutex = NULL;

#define WINOVERRIDE_BINDHOOK(name) \
    if(name##_old) { \
        MH_CreateHook(name##_old, (LPVOID)(name##_hook), (LPVOID*)(&name##_org)); \
        LOGi("WINOVERRIDE_BINDHOOK " #name " %p -> %p\n", name##_old, name##_hook); \
        MH_EnableHook(name##_old); \
        name##_mutex = CreateMutex(NULL, FALSE, NULL); \
    }

#define WINOVERRIDE_UNBINDHOOK(name) \
    if(name##_old) {\
        MH_DisableHook(name##_old); \
        CloseHandle(name##_mutex); \
        LOGi("WINOVERRIDE_UNBINDHOOK " #name " %p\n", name##_old); \
    }

#define WINOVERRIDE_ENTERHOOK(name) \
    WaitForSingleObject(name##_mutex, INFINITE); \
    t##name pfn = name##_org;

#define WINOVERRIDE_LEAVEHOOK(name) \
    ReleaseMutex(name##_mutex);

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

typedef NTSTATUS (NTAPI *tNtOpenFile)(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions);

typedef NTSTATUS(NTAPI* tNtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN OPTIONAL HANDLE FileHandle);

typedef NTSTATUS(NTAPI* tNtCreateSectionEx)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN OPTIONAL HANDLE FileHandle,
    IN OUT PVOID ExtendedParameters,
    ULONG ExtendedParameterCount);

typedef NTSTATUS(NTAPI* tNtQueryAttributesFile)(
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    OUT PFILE_BASIC_INFORMATION FileAttributes);

typedef NTSTATUS(NTAPI* tNtQueryFullAttributesFile)(
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    OUT PFILE_NETWORK_OPEN_INFORMATION  FileInformation);

typedef NTSTATUS(NTAPI* tNtQueryInformationFile)(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass);

typedef NTSTATUS(NTAPI* tNtQueryDirectoryFile)(
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    IN BOOLEAN ReturnSingleEntry,
    IN OPTIONAL PUNICODE_STRING FileName,
    IN BOOLEAN RestartScan);

typedef NTSTATUS(NTAPI* tNtQueryDirectoryFileEx)(
    IN HANDLE FileHandle,
    IN HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    IN ULONG QueryFlags,
    IN OPTIONAL PUNICODE_STRING FileName);

WINOVERRIDE_DEFINEHOOK(NtCreateFile);
WINOVERRIDE_DEFINEHOOK(NtOpenFile);
WINOVERRIDE_DEFINEHOOK(NtCreateSection);
WINOVERRIDE_DEFINEHOOK(NtCreateSectionEx);
WINOVERRIDE_DEFINEHOOK(NtQueryAttributesFile);
WINOVERRIDE_DEFINEHOOK(NtQueryFullAttributesFile);
WINOVERRIDE_DEFINEHOOK(NtQueryInformationFile);
WINOVERRIDE_DEFINEHOOK(NtQueryDirectoryFile);
WINOVERRIDE_DEFINEHOOK(NtQueryDirectoryFileEx);

static BOOL _redirect_path(const POBJECT_ATTRIBUTES ObjectAttributes, wchar_t *rel, wchar_t *target)
{
    if(!ObjectAttributes || !ObjectAttributes->ObjectName || !rel || !target) return FALSE;
    wchar_t cwd[MAX_PATH] = { 0 };
    GetCurrentDirectoryW(MAX_PATH, cwd);
    if(winoverride_relpathw(ObjectAttributes->ObjectName->Buffer, cwd, rel))
    {
        if (wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\??\\"))
        {
            wcscpy(target, L"\\??\\");
            wcscat(target, cwd);
            wcscat(target, L"\\");
        }
        wcscat(target, WINOVERRIDE_REDIRECTDIRW L"\\");
        wcscat(target, rel);
        return TRUE;
    }
    return FALSE;
}

static void _parse_query(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
    int i = 0;
    size_t cur = 0;
    PFILE_FULL_DIR_INFORMATION ffdirinfo = NULL;
    PFILE_BOTH_DIR_INFORMATION fbdirinfo = NULL;
    PFILE_STANDARD_INFORMATION fstdinfo = NULL;
    PFILE_NAME_INFORMATION fnameinfo = NULL;
    PFILE_ALL_INFORMATION fallinfo = NULL;

    switch ((int)FileInformationClass)
    {
    case 2: // FileFullDirectoryInformation (2)
        do
        {
            ffdirinfo = (PFILE_FULL_DIR_INFORMATION)((size_t)FileInformation + cur);
            // LOGLi(L"FileFullDirectoryInformation %d %ls\n", i, ffdirinfo->FileName);
            cur += ffdirinfo->NextEntryOffset;
            i++;
        } while (ffdirinfo->NextEntryOffset && cur < Length);
        break;
    case 3: // FileBothDirectoryInformation (3)
        do
        {
            fbdirinfo = (PFILE_BOTH_DIR_INFORMATION)((size_t)FileInformation + cur);
            // LOGLi(L"FileBothDirectoryInformation %d %ls\n", i, fbdirinfo->FileName);
            cur += fbdirinfo->NextEntryOffset;
            i++;
        } while (fbdirinfo->NextEntryOffset && cur < Length);
        break;
    case 5: // FileStandardInformation (5)
        fstdinfo = (PFILE_STANDARD_INFORMATION)FileInformation;
        break;
    case 9: // FileNameInformation (9)
    case 48: // FileNormalizedNameInformation
        fnameinfo = (PFILE_NAME_INFORMATION)FileInformation;
        break;
    case 14: // FilePositionInformation (14)
        break;
    case 18: // FileAllInformation (18)
        fallinfo = (PFILE_ALL_INFORMATION)FileInformation;
        break;
    case 68: // FileStatInformation (68)
        break;
    default:
        break;
    }
}

size_t winoverride_relpathw(const wchar_t* srcpath, const wchar_t* basepath, wchar_t* relpath)
{
    if (!srcpath || !basepath || !relpath) return 0;

    relpath[0] = L'\0';
    if (wcslen(srcpath) >= 7 && wcsncmp(srcpath, L"\\Device", 7) == 0) return 0;
    if (wcslen(srcpath) >= 7 && wcsncmp(srcpath, L"\\DEVICE", 7) == 0) return 0;
    if (wcslen(srcpath) >= 4 && wcsncmp(srcpath, L"\\??\\", 4) == 0) // nt global path
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
    if (relpath[0] == L'\\') offset = 1;
    else if (relpath[0] == L'.' && relpath[1] == L'\\') offset = 2;
    if (offset > 0) wcsncpy(relpath, relpath + offset, wcslen(relpath) + 1 - offset);

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
    IN ULONG EaLength)
{
    WINOVERRIDE_ENTERHOOK(NtCreateFile);
    NTSTATUS status = -1;
    BOOL flag_redirect = FALSE;
    wchar_t rel[MAX_PATH] = { 0 }, target[MAX_PATH] = { 0 };

    if ((DesiredAccess & FILE_GENERIC_READ) || (DesiredAccess & FILE_GENERIC_EXECUTE))
    {
        if (_redirect_path(ObjectAttributes, rel, target))
        {
            PUNICODE_STRING pustrorg = ObjectAttributes->ObjectName;
            UNICODE_STRING ustr = {(USHORT)wcslen(target) * 2, sizeof(target), target};
            ObjectAttributes->ObjectName = &ustr;
            status = pfn(FileHandle, DesiredAccess,
                ObjectAttributes, IoStatusBlock, AllocationSize,
                FileAttributes, ShareAccess, CreateDisposition,
                CreateOptions, EaBuffer, EaLength);
            ObjectAttributes->ObjectName = pustrorg;

            if (NT_SUCCESS(status))
            {
                flag_redirect = TRUE;
                LOGLi(L"REDIRECT %ls handle=%p\n", rel, *FileHandle);
            }
        }
    }

    if (!flag_redirect)
    {
        status = pfn(FileHandle, DesiredAccess,
            ObjectAttributes, IoStatusBlock, AllocationSize,
            FileAttributes, ShareAccess, CreateDisposition,
            CreateOptions, EaBuffer, EaLength);
        if(rel[0]) LOGLi(L"FILE %ls %ld\n", rel, status);
    }

    WINOVERRIDE_LEAVEHOOK(NtCreateFile);
    return status;
}

static NTSTATUS NTAPI NtOpenFile_hook(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions)
{
    WINOVERRIDE_ENTERHOOK(NtOpenFile);
    NTSTATUS status = -1;
    BOOL flag_redirect = FALSE;
    wchar_t rel[MAX_PATH] = { 0 }, target[MAX_PATH] = { 0 };

    if ((DesiredAccess & FILE_GENERIC_READ) || (DesiredAccess & FILE_GENERIC_EXECUTE))
    {
        if (_redirect_path(ObjectAttributes, rel, target))
        {
            PUNICODE_STRING pustrorg = ObjectAttributes->ObjectName;
            UNICODE_STRING ustr = { (USHORT)wcslen(target) * 2, sizeof(target), target };
            ObjectAttributes->ObjectName = &ustr;
            status = pfn(FileHandle, DesiredAccess,
                ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
            ObjectAttributes->ObjectName = pustrorg;

            if (NT_SUCCESS(status))
            {
                flag_redirect = TRUE;
                LOGLi(L"REDIRECT %ls handle=%p\n", rel, *FileHandle);
            }
        }
    }

    if (!flag_redirect)
    {
        status = pfn(FileHandle, DesiredAccess,
            ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
        if (rel[0]) LOGLi(L"FILE %ls %ld\n", rel, status);
    }

    WINOVERRIDE_LEAVEHOOK(NtOpenFile);
    return status;
}

// might not used for check file
static NTSTATUS NTAPI NtCreateSection_hook(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN OPTIONAL HANDLE FileHandle)
{
    WINOVERRIDE_ENTERHOOK(NtCreateSection);
    NTSTATUS status = -1;
    status = pfn(SectionHandle, DesiredAccess,
        ObjectAttributes, MaximumSize, SectionPageProtection,
        AllocationAttributes, FileHandle);
    WINOVERRIDE_LEAVEHOOK(NtCreateSection);
    return status;
}

static NTSTATUS NTAPI NtCreateSectionEx_hook(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN OPTIONAL HANDLE FileHandle,
    IN OUT PVOID ExtendedParameters,
    ULONG ExtendedParameterCount)
{
    WINOVERRIDE_ENTERHOOK(NtCreateSectionEx);
    NTSTATUS status = -1;
    status  = pfn(SectionHandle, DesiredAccess,
        ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, 
        FileHandle, ExtendedParameters, ExtendedParameterCount);
    WINOVERRIDE_LEAVEHOOK(NtCreateSectionEx);
    return status;
}

static NTSTATUS NTAPI NtQueryAttributesFile_hook(
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    OUT PFILE_BASIC_INFORMATION FileAttributes)
{
    WINOVERRIDE_ENTERHOOK(NtQueryAttributesFile);
    NTSTATUS status = -1;
    status = pfn(ObjectAttributes, FileAttributes);
    WINOVERRIDE_LEAVEHOOK(NtQueryAttributesFile);
    return status;
}

// this function is important for file size
static NTSTATUS NTAPI NtQueryFullAttributesFile_hook(
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    OUT PFILE_NETWORK_OPEN_INFORMATION  FileInformation)
{
    WINOVERRIDE_ENTERHOOK(NtQueryFullAttributesFile);
    NTSTATUS status = -1;
    BOOL flag_redirect = FALSE;
    wchar_t rel[MAX_PATH] = { 0 }, target[MAX_PATH] = { 0 };

    if (_redirect_path(ObjectAttributes, rel, target))
    {
        PUNICODE_STRING pustrorg = ObjectAttributes->ObjectName;
        UNICODE_STRING ustr = { (USHORT)wcslen(target) * 2, sizeof(target), target };
        ObjectAttributes->ObjectName = &ustr;
        status = pfn(ObjectAttributes, FileInformation);
        ObjectAttributes->ObjectName = pustrorg;

        if (NT_SUCCESS(status))
        {
            flag_redirect = TRUE;
            LOGLi(L"REDIRECT %ls size=0x%llx\n", rel, FileInformation->EndOfFile.QuadPart);
        }
    }

    if(!flag_redirect)
    {
        status = pfn(ObjectAttributes, FileInformation);
        if (rel[0] && NT_SUCCESS(status)) LOGLi(L"FILE %ls size=0x%llx\n", rel, FileInformation->EndOfFile.QuadPart);
    }

    WINOVERRIDE_LEAVEHOOK(NtQueryFullAttributesFile);
    return status;
}

// might not need to redirect
static NTSTATUS NTAPI NtQueryInformationFile_hook(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass)
{
    WINOVERRIDE_ENTERHOOK(NtQueryInformationFile);
    NTSTATUS status = -1;
    status = pfn(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    // LOGLi(L"handle=%p %d\n", FileHandle, FileInformationClass);
    _parse_query(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    WINOVERRIDE_LEAVEHOOK(NtQueryInformationFile);
    return status;
}

static NTSTATUS NTAPI NtQueryDirectoryFile_hook(
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    IN BOOLEAN ReturnSingleEntry,
    IN OPTIONAL PUNICODE_STRING FileName,
    IN BOOLEAN RestartScan)
{
    WINOVERRIDE_ENTERHOOK(NtQueryDirectoryFile);
    NTSTATUS status = -1;
    status  =  pfn(FileHandle, Event,
        ApcRoutine, ApcContext, IoStatusBlock,
        FileInformation, Length, FileInformationClass,
        ReturnSingleEntry, FileName, RestartScan);
    // LOGLi(L"handle=%p %d\n", FileHandle, FileInformationClass);
    _parse_query(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    WINOVERRIDE_LEAVEHOOK(NtQueryDirectoryFile);
    return status;
}

static NTSTATUS NTAPI NtQueryDirectoryFileEx_hook(
    IN HANDLE FileHandle,
    IN HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    IN ULONG QueryFlags,
    IN OPTIONAL PUNICODE_STRING FileName)
{
    WINOVERRIDE_ENTERHOOK(NtQueryDirectoryFileEx);
    NTSTATUS status = -1;
    status = pfn(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, FileInformation, Length,
        FileInformationClass, QueryFlags, FileName);
    // LOGLi(L"handle=%p %d\n", FileHandle, FileInformationClass);
    _parse_query(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    WINOVERRIDE_LEAVEHOOK(NtQueryDirectoryFileEx);
    return status;
}

void winoverride_banner()
{
    LOGi("winoverride v0.1.3, developed by devseed\n");
    
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
    NtOpenFile_old = GetProcAddress(ntdll, "NtOpenFile");
    WINOVERRIDE_BINDHOOK(NtOpenFile);
    NtCreateSection_old = GetProcAddress(ntdll, "NtCreateSection");
    WINOVERRIDE_BINDHOOK(NtCreateSection);
    NtCreateSectionEx_old = GetProcAddress(ntdll, "NtCreateSectionEx");
    WINOVERRIDE_BINDHOOK(NtCreateSectionEx);
    NtQueryAttributesFile_old = GetProcAddress(ntdll, "NtQueryAttributesFile");
    WINOVERRIDE_BINDHOOK(NtQueryAttributesFile);
    NtQueryFullAttributesFile_old = GetProcAddress(ntdll, "NtQueryFullAttributesFile");
    WINOVERRIDE_BINDHOOK(NtQueryFullAttributesFile);
    NtQueryInformationFile_old = GetProcAddress(ntdll, "NtQueryInformationFile");
    WINOVERRIDE_BINDHOOK(NtQueryInformationFile);
    NtQueryDirectoryFile_old = GetProcAddress(ntdll, "NtQueryDirectoryFile");
    WINOVERRIDE_BINDHOOK(NtQueryDirectoryFile);
    NtQueryDirectoryFileEx_old = GetProcAddress(ntdll, "NtQueryDirectoryFileEx");
    WINOVERRIDE_BINDHOOK(NtQueryDirectoryFileEx);
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

/**
 * history:
 *   v0.1, initial version
 *   v0.1.1, seperate to single header file
 *   v0.1.2, add NtOpenFile, relpathw string length check
 *   v0.1.3, add NtCreateSection, NtCreateSectionEx,
 *          NtQueryAttributesFile, NtQueryFullAttributesFile,
            NtQueryInformationFile, NtQueryDirectoryFile
 */