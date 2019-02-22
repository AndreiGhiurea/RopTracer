#include "utils.h"

EXE_FILE gExeFile = { 0 };
DWORD gCallCount = { 0 };

STATUS
RtrSuspendThreads(VOID)
{
    DWORD processId = GetCurrentProcessId();
    DWORD currentThreadId = GetCurrentThreadId();

    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
    if (INVALID_HANDLE_VALUE == hThreadSnapshot)
    {
        printf("[ERROR] CreateToolhelp32Snapshot failed: %d\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnapshot, &threadEntry))
    {
        printf("[ERROR] Thread32First failed: %d\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    do
    {
        if (threadEntry.th32OwnerProcessID == processId
            && threadEntry.th32ThreadID != currentThreadId)
        {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
                threadEntry.th32ThreadID);
            if (!hThread)
            {
                printf("[ERROR] OpenThread failed: %d\n", GetLastError());
            }

            SuspendThread(hThread);
            CloseHandle(hThread);
        }
    } while (Thread32Next(hThreadSnapshot, &threadEntry));

    CloseHandle(hThreadSnapshot);

    return STATUS_SUCCESS;
}

STATUS
RtrResumeThreads(VOID)
{
    DWORD processId = GetCurrentProcessId();
    DWORD currentThreadId = GetCurrentThreadId();

    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
    if (INVALID_HANDLE_VALUE == hThreadSnapshot)
    {
        printf("[ERROR] CreateToolhelp32Snapshot failed: %d\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnapshot, &threadEntry))
    {
        printf("[ERROR] Thread32First failed: %d\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    do
    {
        if (threadEntry.th32OwnerProcessID == processId
            && threadEntry.th32ThreadID != currentThreadId)
        {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
                threadEntry.th32ThreadID);
            if (!hThread)
            {
                printf("[ERROR] OpenThread failed: %d\n", GetLastError());
            }

            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    } while (Thread32Next(hThreadSnapshot, &threadEntry));

    CloseHandle(hThreadSnapshot);

    return STATUS_SUCCESS;
}