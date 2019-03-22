#include "injector.h"

#define DLL_NAME	"RopTracerDll.dll"
#define EXE_NAME	"RopTracerVuln.exe"

int main(void)
{
    BOOL bErr;

    // Get the list of process identifiers.
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return 1;
    }

    // Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the name and process identifier for each process.
    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            CHAR szProcessName[MAX_PATH] = "<unknown>";

            // Get a handle to the process.
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION || PROCESS_VM_READ ,
                FALSE, aProcesses[i]);

            // Get the process name.
            if (NULL != hProcess)
            {
                HMODULE hMod;

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
                    &cbNeeded))
                {
                    GetModuleBaseName(hProcess, hMod, szProcessName,
                        sizeof(szProcessName) / sizeof(CHAR));
                }
            }

            // Print the process name and identifier.
            if (strcmp(EXE_NAME, szProcessName) == 0)
            {
                printf("Found %s - (PID: %u)\n", szProcessName, aProcesses[i]);
                printf("Trying to inject hack!\n");

                bErr = InjectDllIntoProcess(hProcess, DLL_NAME);
                printf("Injection %s\n", bErr ? "Succeeded" : "Failed");
            }

            // Release the handle to the process.
            CloseHandle(hProcess);
        }
    }

    return 0;
}