#include "handler.h"
#include "emu.h"

LONG WINAPI
BreakpointHandler(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
    )
{
    LONG returnValue = EXCEPTION_EXECUTE_HANDLER;
    DWORD exceptioncode;
    PLIST_ENTRY list;
    BOOL found = FALSE;
    STATUS status = STATUS_SUCCESS;

    exceptioncode = ExceptionInfo->ExceptionRecord->ExceptionCode;

    switch (exceptioncode)
    {
    case EXCEPTION_BREAKPOINT:
        MessageBox(NULL, "Breakpoint Exception", "RopTracerDll.dll", MB_ICONINFORMATION);
        
        list = gExeFile.RetPatchList.Flink;
        while (list != &gExeFile.RetPatchList && !found)
        {
            PRET_PATCH pRetPatch = CONTAINING_RECORD(list, RET_PATCH, Link);

            if ((QWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == pRetPatch->Address)
            {
                found = TRUE;

                if (pRetPatch->Disabled)
                {
                    goto _continue;
                }

                // Found the patch
                // TODO: Some checks
                printf("[INFO] Found the patch!\n");

                /// Patch original instruction
                // *(PBYTE)ExceptionInfo->ExceptionRecord->ExceptionAddress = pRetPatch->InstructionBytes[0];
                // for (int i = 0; i < pRetPatch->Instruction.length; i++)
                // {
                //     *((PBYTE)ExceptionInfo->ExceptionRecord->ExceptionAddress + i) = pRetPatch->InstructionBytes[i];
                // }

                status = EmulateInstruction(pRetPatch->Instruction, ExceptionInfo);
                if (!SUCCESS(status))
                {
                    printf("[ERROR] EmulateInstruction failed!\n");
                }

                printf("[INFO] Exception address     : 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
                returnValue = EXCEPTION_CONTINUE_EXECUTION;
            }

        _continue:
            list = list->Flink;
        }

        break;
    case EXCEPTION_SINGLE_STEP:
        printf("[INFO] Single Stepping\n");
        return EXCEPTION_CONTINUE_EXECUTION;
        break;
    default:
        printf("EXCEPTION ADDRESS: 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
        printf("EXCEPTION CODE: 0x%08lx\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
        MessageBox(NULL, "Unknown Exception", "RopTracerDll.dll", MB_ICONERROR);
        return EXCEPTION_EXECUTE_HANDLER;
        break;
    }

    return returnValue;
}
