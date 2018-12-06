#include "emu.h"

void EmulateRetInstruction(PEXCEPTION_POINTERS ExceptionInfo)
{
    QWORD retAddress;

    retAddress = *(PDWORD64)ExceptionInfo->ContextRecord->Rsp;
    printf("RET ADDRESS: 0x%016llx\n", retAddress);
    ExceptionInfo->ContextRecord->Rip = retAddress;
}