#ifndef _NTAPI_H_
#define _NTAPI_H_

#include <Windows.h>

#ifdef __cplusplus  
extern "C" {
#endif 

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef NTSTATUS
(NTAPI *PFUN_NtCreateSection)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    PVOID              ObjectAttributes,        // POBJECT_ATTRIBUTES
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
    );

typedef NTSTATUS
(NTAPI *PFUN_NtMapViewOfSection)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID           *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
    );

typedef NTSTATUS
(NTAPI *PFUN_NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
    );

typedef  NTSTATUS
(NTAPI *PFUN_NtClose)(
    IN HANDLE Handle
    );

typedef NTSTATUS
(NTAPI *PFUN_NtQueryInformationProcess)(
    IN HANDLE               ProcessHandle,
    IN DWORD                ProcessInformationClass,    // PROCESSINFOCLASS
    OUT PVOID               ProcessInformation,
    IN ULONG                ProcessInformationLength,
    OUT PULONG              ReturnLength OPTIONAL
    );

typedef struct _NT_API
{
    PFUN_NtCreateSection NtCreateSection;
    PFUN_NtMapViewOfSection NtMapViewOfSection;
    PFUN_NtUnmapViewOfSection NtUnmapViewOfSection;
    PFUN_NtQueryInformationProcess NtQueryInformationProcess;
    PFUN_NtClose NtClose;
} NT_API, *PNT_API;

BOOLEAN
NtApiFindAll(
    _Out_ NT_API *NtApi
    );

#ifdef __cplusplus 
}
#endif 
#endif // !_NTAPI_H_
