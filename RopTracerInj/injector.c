#include "injector.h"
#include <stdio.h>
#include <Psapi.h>

BOOLEAN
InjectDllIntoProcess(
    _In_ const DWORD Pid,
    _In_ const PCHAR DllPath
)
{
    HANDLE hProcess = NULL;
    CHAR fName[MAX_PATH] = { 0 };
    PVOID pProcessMem = NULL;
    HANDLE hThread = NULL;
    HMODULE hKernel32 = NULL;
    LPTHREAD_START_ROUTINE pLoadLib;
    DWORD threadId;
    HMODULE hMods[4096];
    DWORD cbNeeded;
    PBYTE rvaLoadLibraryA;
    unsigned int i;
    BOOLEAN success = TRUE;

    if (strlen(DllPath) >= sizeof(fName))
    {
        printf("Dll path too big!\n");
        success = FALSE;
        goto cleanup_and_exit;
    }

    // Open the process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
    if (NULL == hProcess)
    {
        printf("OpenProcess failed: %d\n", GetLastError());
        success = FALSE;
        goto cleanup_and_exit;
    }

    memcpy(fName, DllPath, strlen(DllPath));

    // Reserve memory for dll's path in the process' memory
    pProcessMem = VirtualAllocEx(hProcess, NULL, sizeof(fName), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NULL == pProcessMem)
    {
        printf("VirtualAllocEx failed: %d\n", GetLastError());
        success = FALSE;
        goto cleanup_and_exit;
    }

    // Write in process' memory dll's path
    if (!WriteProcessMemory(hProcess, pProcessMem, fName, sizeof(fName), NULL))
    {
        printf("WriteProcessMemory failed: %d\n", GetLastError());
        success = FALSE;
        goto cleanup_and_exit;
    }

    //          Calculate RVA to LoadLibraryA
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

    rvaLoadLibraryA = (PBYTE)((SIZE_T)pLoadLib - (SIZE_T)hKernel32);
    printf("RVA is %p\n", rvaLoadLibraryA);

    // We search for the "real" Kernel32.dll of our process(this special case is for the ASM app)
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
            {
                // Print the module name and handle value.
                printf(TEXT("\t%s 0x%p\n"), szModName, hMods[i]);

                // Get the "real" handle to kernel32
                if (0 == _stricmp(szModName, KERNEL32_PATH))
                {
                    pLoadLib = (LPTHREAD_START_ROUTINE)((SIZE_T)hMods[i] + (SIZE_T)rvaLoadLibraryA);

                    printf("Kernel32 ASM found @ %p\n", hMods[i]);
                    printf("LoadLibraryA ASM found @ %p\n", pLoadLib);

                    break;
                }
            }
        }
    }

    // check if hMods array is too small to hold all module handles
    if (sizeof(hMods) < cbNeeded)
    {
        printf("[ERROR] hMods array is too small to hold all module handles for the process\n");
        success = FALSE;
        goto cleanup_and_exit;
    }

    // Create a remote thread starting at LoadLibrary
    hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLib, pProcessMem, 0, &threadId);
    if (NULL == hThread)
    {
        printf("CreateRemoteThread failed: %d\n", GetLastError());
        success = FALSE;
        goto cleanup_and_exit;
    }

    printf("Remote thread id: %d\n", threadId);

    success = TRUE;

cleanup_and_exit:
    if (NULL != hProcess)
    {
        CloseHandle(hProcess);
    }

    if (NULL != hThread)
    {
        CloseHandle(hThread);
    }

    if (NULL != pProcessMem)
    {
        VirtualFreeEx(hProcess, pProcessMem, 0, MEM_FREE);
    }

    return success;
}