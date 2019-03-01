#include "handler.h"
#include "emu.h"

LONG WINAPI
RtrBreakpointHandler(
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
        list = gExeFile.InstructionPatchList.Flink;
        while (list != &gExeFile.InstructionPatchList && !found)
        {
            PRET_PATCH pInstructionPatch = CONTAINING_RECORD(list, RET_PATCH, Link);

            if ((QWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == pInstructionPatch->Address)
            {
				printf("[INFO] Found the patch!\n");
				printf("[INFO] Instruction Addr: 0x%016llx\n", pInstructionPatch->Address);
				printf("[INFO] Exception address     : 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);

                found = TRUE;

                if (pInstructionPatch->Disabled)
                {
                    goto _continue;
                }

                // Found the patch
                // TODO: Some checks
                printf("[INFO] Found the patch!\n");
				printf("[INFO] Instruction Addr: 0x%016llx\n", pInstructionPatch->Address);

                status = RtrEmulateInstruction(pInstructionPatch->Instruction, ExceptionInfo);
                if (!SUCCESS(status))
                {
                    printf("[ERROR] RtrEmulateInstruction failed!\n");
                }

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
        return EXCEPTION_CONTINUE_SEARCH;
        break;
    }

    return returnValue;
}
