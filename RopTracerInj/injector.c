#include "injector.h"
#include <stdio.h>
#include "ntapi.h"
#include <Psapi.h>

BOOLEAN
InjectDllIntoProcess(
    _In_ const HANDLE Process,
    _In_ const PCHAR DllPath
)
{
    NT_API ntApi = { 0 };
    HANDLE hThread = NULL;
    DWORD pathLen;
    PCHAR pDllPath;
    HMODULE hKernel32 = NULL;
    LPTHREAD_START_ROUTINE pLoadLib;
    DWORD threadId;
    BOOLEAN success = TRUE;
    LARGE_INTEGER liSizeOfSection;
    HANDLE hSection;
    NTSTATUS status;
    LPVOID pDllPatchAttacker, pDllPatchTarget;
    SIZE_T viewSize = 0;

    pDllPatchAttacker = pDllPatchTarget = NULL;

    printf("[INFO] DLL Name: %s\n", DllPath);

    if (strlen(DllPath) >= MAX_PATH)
    {
        printf("[ERROR] Dll path too big!\n");
        success = FALSE;
        goto cleanup_and_exit;
    }

    pathLen = (DWORD)(GetCurrentDirectoryA(0, NULL) + strlen(DllPath) + 2);

    pDllPath = (PCHAR)malloc(pathLen);

    GetCurrentDirectoryA(pathLen, pDllPath);

    strcat_s(pDllPath, pathLen, "\\");

    strcat_s(pDllPath, pathLen, DllPath);

    printf("[INFO] Full DLL Path: %s\n", pDllPath);

    // Find ntdll api.
    if (!NtApiFindAll(&ntApi))
    {
        printf("[ERROR] NtApiInit failed!\n");
        success = FALSE;
        goto cleanup_and_exit;
    }

    // Size for the first section, dll path
    liSizeOfSection.HighPart = 0;
    liSizeOfSection.LowPart = pathLen;

    // Create a new section for dll path
    status = ntApi.NtCreateSection(&hSection, SECTION_ALL_ACCESS,
        NULL, &liSizeOfSection, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!SUCCEEDED(status))
    {
        printf("[ERROR] NtCreateSection failed: 0x%08x\n", status);
        success = FALSE;
        goto cleanup_and_exit;
    }

    // Map view of section for current process
    status = ntApi.NtMapViewOfSection(hSection, GetCurrentProcess(),
        &pDllPatchAttacker, 0, 0, 0, &viewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);
    if (!SUCCEEDED(status))
    {
        printf("[ERROR] Attacker NtMapViewOfSection failed: 0x%08x\n", status);
        success = FALSE;
        goto cleanup_and_exit;
    }

    // Map view of section for target process
    status = ntApi.NtMapViewOfSection(hSection, Process,
        &pDllPatchTarget, 0, 0, 0, &viewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);
    if (!SUCCEEDED(status))
    {
        printf("[ERROR] Target NtMapViewOfSection failed: 0x%08x\n", status);
        success = FALSE;
        goto cleanup_and_exit;
    }

    // Copy payload to section of memory
    memcpy(pDllPatchAttacker, pDllPath, pathLen);

    // Unmap memory in the current process
    status = ntApi.NtUnmapViewOfSection(GetCurrentProcess(), pDllPatchAttacker);
    if (!SUCCEEDED(status))
    {
        printf("[ERROR] NtUnmapViewOfSection failed: 0x%08x\n", status);
        success = FALSE;
        goto cleanup_and_exit;
    }

    // Close section
    status = ntApi.NtClose(hSection);
    if (!SUCCEEDED(status))
    {
        printf("[ERROR] NtClose failed: 0x%08x\n", status);
        success = FALSE;
        goto cleanup_and_exit;
    }

    // Calculate RVA to LoadLibraryA
    // Get handle to kernel32
    hKernel32 = GetModuleHandle(KERNEL32_NAME);
    if (NULL == hKernel32)
    {
        printf("GetModuleHandle failed: %d\n", GetLastError());
        success = FALSE;
        goto cleanup_and_exit;
    }

    printf("[INFO] kernel32.dll found @ %p\n", hKernel32);

    // Get address of LoadLibrary
    pLoadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, LOADLIBRARYA_NAME);
    if (NULL == pLoadLib)
    {
        printf("[ERROR] GetProcAddress failed: %d\n", GetLastError());
        success = FALSE;
        goto cleanup_and_exit;
    }

    printf("[INFO] LoadLibraryA found @ %p\n\n", pLoadLib);

    // Create a remote thread starting at LoadLibrary
    hThread = CreateRemoteThread(Process, NULL, 0, pLoadLib, pDllPatchTarget, 0, &threadId);
    if (NULL == hThread)
    {
        printf("CreateRemoteThread failed: %d\n", GetLastError());
        success = FALSE;
        goto cleanup_and_exit;
    }

    printf("[INFO] Remote Thread ID: %d\n", threadId);

    // Unmap memory in the current process
    status = ntApi.NtUnmapViewOfSection(Process, pDllPatchTarget);
    if (!SUCCEEDED(status))
    {
        printf("[ERROR] NtUnmapViewOfSection failed: 0x%08x\n", status);
        success = FALSE;
        goto cleanup_and_exit;
    }
    success = TRUE;

cleanup_and_exit:
    if (NULL != hThread)
    {
        CloseHandle(hThread);
    }

    return success;
}
