#include "utils.h"
#include "tracer.h"

INT
main(INT Argc, PCHAR Argv[])
{
    UNREFERENCED_PARAMETER(Argc);
    UNREFERENCED_PARAMETER(Argv);

    STATUS status = STATUS_SUCCESS;
    DWORD processId;
    CHAR processName[255] = { 0 };

    // This means the tracer was started with arguments (process name, process id). Used for GUI injector.
    if (Argc == 3)
    {
        strcpy_s(processName, sizeof(processName) - 1, Argv[1]);
        processId = atoi(Argv[2]);
        goto skip_proc_search;
    }

read_name:
    printf("Name of process to inject: ");
    scanf_s("%s", processName, 255);

#ifndef _DEBUG
    FreeConsole();
#endif

    status = RtrFindPidFromName(processName, &processId);
    if (!SUCCEEDED(status))
    {
        // LOG("[ERROR] RtrFindPidFromName failed: 0x%08x\n", status);
        LOG("Proccess with given name not found! Try again.\n");
        goto read_name;
        // return STATUS_UNSUCCESSFUL;
    }

skip_proc_search:
    LOG("[TRACER] Found process: %s\n", processName);
    LOG("[TRACER] Process ID: %d\n", processId);

    // Initialize gExeFile list head for RET patches
    InitializeListHead(&gExeFile.InstructionPatchList);

    status = RtrStartTrace(processId);
    if (!SUCCEEDED(status))
    {
        LOG("[ERROR] RtrStartTrace failed: 0x%08x\n", status);
    }

    return status;
}