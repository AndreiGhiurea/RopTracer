#include "injector.h"
#include <stdio.h>
#include <Psapi.h>

BOOLEAN
InjectDllIntoProcess(
    _In_ const HANDLE Process,
    _In_ const PCHAR DllPath
)
{
    CHAR fName[MAX_PATH] = { 0 };
    PVOID pProcessMem = NULL;
    HANDLE hThread = NULL;
    HMODULE hKernel32 = NULL;
    LPTHREAD_START_ROUTINE pLoadLib;
    DWORD threadId;
    BOOLEAN success = TRUE;

    if (strlen(DllPath) >= sizeof(fName))
    {
        printf("Dll path too big!\n");
        success = FALSE;
        goto cleanup_and_exit;
    }

    if (!GetFullPathName(DllPath, MAX_PATH, fName, NULL))
    {
        printf("GetFullPathName failed: %d\n", GetLastError());
    }
    
    printf("Full DLL path: %s\n", fName);

    // Reserve memory for dll's path in the process' memory
    pProcessMem = VirtualAllocEx(Process, NULL, strlen(fName) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (NULL == pProcessMem)
    {
        printf("VirtualAllocEx failed: %d\n", GetLastError());
        success = FALSE;
        goto cleanup_and_exit;
    }

    // Write in process' memory dll's path
    if (!WriteProcessMemory(Process, pProcessMem, fName, strlen(fName) + 1, NULL))
    {
        printf("WriteProcessMemory failed: %d\n", GetLastError());
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

    printf("Kernel32 found @ %p\n", hKernel32);

    // Get address of LoadLibrary
    pLoadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, LOADLIBRARYA_NAME);
    if (NULL == pLoadLib)
    {
        printf("GetProcAddress failed: %d\n", GetLastError());
        success = FALSE;
        goto cleanup_and_exit;
    }

    printf("LoadLibraryA found @ %p\n\n", pLoadLib);

    // Create a remote thread starting at LoadLibrary
    hThread = CreateRemoteThread(Process, NULL, 0, pLoadLib, pProcessMem, 0, &threadId);
    if (NULL == hThread)
    {
        printf("CreateRemoteThread failed: %d\n", GetLastError());
        success = FALSE;
        goto cleanup_and_exit;
    }

    printf("Remote thread id: %d\n", threadId);

    success = TRUE;

cleanup_and_exit:
    if (NULL != hThread)
    {
        CloseHandle(hThread);
    }

    if (NULL != pProcessMem)
    {
        VirtualFreeEx(Process, pProcessMem, 0, MEM_FREE);
    }

    return success;
}
