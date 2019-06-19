#include "emu.h"

STATUS 
RtrEmulateInstruction(
    ZydisDecodedInstruction Instruction,
    PEXCEPTION_POINTERS ExceptionInfo
    )
{
    STATUS status;

    Instruction.mnemonic = ZYDIS_MNEMONIC_RET;
    switch (Instruction.mnemonic)
    {
    case ZYDIS_MNEMONIC_RET:
#ifdef _WIN64
        ExceptionInfo->ContextRecord->Rip = *(PSIZE_T)ExceptionInfo->ContextRecord->Rsp;
        ExceptionInfo->ContextRecord->Rsp += (SIZE_T)8;
#else
        ExceptionInfo->ContextRecord->Eip = *(PSIZE_T)ExceptionInfo->ContextRecord->Esp;
        ExceptionInfo->ContextRecord->Esp += (SIZE_T)4;
#endif
        status = STATUS_SUCCESS;
        break;
    default:
        LOG("[EMU] Instruction not supported\n");
        status = STATUS_UNSUCCESSFUL;
        break;
    }

    return status;
}