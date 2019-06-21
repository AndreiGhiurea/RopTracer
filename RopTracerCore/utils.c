#include "utils.h"
#include <psapi.h>

EXE_FILE gExeFile = { 0 };
DWORD gCallCount = { 0 };

STATUS
RtrFindPidFromName(
    _In_ LPSTR ProcessName, 
    _Out_ DWORD* Pid
    )
{
    BOOL found = FALSE;
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    HANDLE hProcess = NULL;
    HMODULE hMod = NULL;
    CHAR szProcessName[MAX_PATH];

    if (!Pid)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    // Get the list of process identifiers.
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        LOG("[ERROR] EnumProcesses failed: %d\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    // Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                aProcesses[i]);
            
            if (NULL != hProcess)
            {
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
                    &cbNeeded))
                {
                    GetModuleBaseName(hProcess, hMod, szProcessName,
                        sizeof(szProcessName) / sizeof(CHAR));

                    if (strcmp(szProcessName, ProcessName) == 0)
                    {
                        *Pid = aProcesses[i];
                        found = TRUE;
                        CloseHandle(hProcess);
                        break;
                    }
                }

                CloseHandle(hProcess);
            }
        }
    }

    if (!found)
    {
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}