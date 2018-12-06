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
                // Do some checks
                printf("[INFO] Found the patch. Do some checks!\n");

                *(PBYTE)ExceptionInfo->ExceptionRecord->ExceptionAddress = pRetPatch->OriginalOpcode;
                // EmulateRetInstruction(ExceptionInfo);
                // ExceptionInfo->ContextRecord->EFlags |= 0x100;
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
        MessageBox(NULL, "Unknown Exception", "RopTracerDll.dll", MB_ICONINFORMATION);
        return EXCEPTION_EXECUTE_HANDLER;
        break;
    }

    return returnValue;
}
