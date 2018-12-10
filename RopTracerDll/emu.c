#include "emu.h"

STATUS 
RtrEmulateInstruction(
    ZydisDecodedInstruction Instruction,
    PEXCEPTION_POINTERS ExceptionInfo
    )
{
    STATUS status;

    switch (Instruction.mnemonic)
    {
    case ZYDIS_MNEMONIC_RET:
        // Get the top of the stack and put it in RIP
        ExceptionInfo->ContextRecord->Rip = *(PDWORD64)ExceptionInfo->ContextRecord->Rsp;
        ExceptionInfo->ContextRecord->Rsp += 8;
        status = STATUS_SUCCESS;
        break;
    default:
        printf("[EMU] Instruction not supported\n");
        status = STATUS_UNSUCCESSFUL;
        break;
    }

    return status;
}