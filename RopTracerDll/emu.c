#include "emu.h"

void EmulateRetInstruction(PEXCEPTION_POINTERS ExceptionInfo)
{
    QWORD retAddress;

    retAddress = *(PDWORD64)ExceptionInfo->ContextRecord->Rsp;
    
    ExceptionInfo->ContextRecord->Rip = retAddress;
}