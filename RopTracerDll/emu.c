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
		printf("[EMU] RSP: 0x%016llx\n", ExceptionInfo->ContextRecord->Rsp);
		printf("[EMU] At RSP: 0x%016llx\n", *(PQWORD)ExceptionInfo->ContextRecord->Rsp);
		
		ExceptionInfo->ContextRecord->Rip = *(PQWORD)ExceptionInfo->ContextRecord->Rsp;
        ExceptionInfo->ContextRecord->Rsp += (QWORD)8;
        
		printf("[EMU] RSP After: 0x%016llx\n", ExceptionInfo->ContextRecord->Rsp);

		status = STATUS_SUCCESS;
        break;
    default:
        printf("[EMU] Instruction not supported\n");
        status = STATUS_UNSUCCESSFUL;
        break;
    }

    return status;
}