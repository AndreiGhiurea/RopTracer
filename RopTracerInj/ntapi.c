#include "ntapi.h"
#include "stdio.h"

//
// NtApiInit
//
BOOLEAN
NtApiFindAll(
    _Out_ NT_API *NtApi
    )
{
    HMODULE hNt;

    if (NULL == NtApi)
    {
        return FALSE;
    }

    hNt = NULL;

    printf("[INFO] Attempt to find ntdll api...\n");

    hNt = GetModuleHandleA("ntdll");
    if (NULL == hNt)
    {
        printf("[ERROR] GetModuleHandleA failed: %d\n", GetLastError());
        return FALSE;
    }

    NtApi->NtCreateSection = (PFUN_NtCreateSection)GetProcAddress(hNt, "NtCreateSection");
    if (NULL == NtApi->NtCreateSection)
    {
        printf("[ERROR] GetProcAddress failed to find NtCreateSection inside ntdll: %d\n", GetLastError());
        return FALSE;
    }

    printf("[INFO] Found NtCreateSection at %p\n", NtApi->NtCreateSection);

    NtApi->NtMapViewOfSection = (PFUN_NtMapViewOfSection)GetProcAddress(hNt, "NtMapViewOfSection");
    if (NULL == NtApi->NtCreateSection)
    {
        printf("[ERROR] GetProcAddress failed to find NtMapViewOfSection inside ntdll: %d\n", GetLastError());
        return FALSE;
    }

    printf("[INFO] Found NtMapViewOfSection at %p\n", NtApi->NtMapViewOfSection);

    NtApi->NtUnmapViewOfSection = (PFUN_NtUnmapViewOfSection)GetProcAddress(hNt, "NtUnmapViewOfSection");
    if (NULL == NtApi->NtCreateSection)
    {
        printf("[ERROR] GetProcAddress failed to find NtUnmapViewOfSection inside ntdll: %d\n", GetLastError());
        return FALSE;
    }

    printf("[INFO] Found NtUnmapViewOfSection at %p\n", NtApi->NtUnmapViewOfSection);

    NtApi->NtQueryInformationProcess = (PFUN_NtQueryInformationProcess)GetProcAddress(hNt, "NtQueryInformationProcess");
    if (NULL == NtApi->NtCreateSection)
    {
        printf("[ERROR] GetProcAddress failed to find NtQueryInformationProcess inside ntdll: %d\n", GetLastError());
        return FALSE;
    }

    printf("[INFO] Found NtQueryInformationProcess at %p\n", NtApi->NtQueryInformationProcess);

    NtApi->NtClose = (PFUN_NtClose)GetProcAddress(hNt, "NtClose");
    if (NULL == NtApi->NtCreateSection)
    {
        printf("[ERROR] GetProcAddress failed to find NtClose inside ntdll: %d\n", GetLastError());
        return FALSE;
    }

    printf("[INFO] Found NtClose at %p\n", NtApi->NtClose);

    printf("[INFO] Found all needed api!\n");

    return TRUE;
}
