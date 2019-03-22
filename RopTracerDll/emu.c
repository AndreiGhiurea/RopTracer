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
#ifdef _WIN64
		ExceptionInfo->ContextRecord->Rip = *(PQWORD)ExceptionInfo->ContextRecord->Rsp;
        ExceptionInfo->ContextRecord->Rsp += (QWORD)8;
#else
        ExceptionInfo->ContextRecord->Eip = *(PQWORD)ExceptionInfo->ContextRecord->Esp;
        ExceptionInfo->ContextRecord->Esp += (QWORD)4;
#endif
		status = STATUS_SUCCESS;
        break;
    default:
        printf("[EMU] Instruction not supported\n");
        status = STATUS_UNSUCCESSFUL;
        break;
    }

    return status;
}