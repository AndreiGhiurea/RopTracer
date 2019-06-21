#include "emu.h"

STATUS 
RtrEmulateInstruction(
    ZydisDecodedInstruction Instruction,
    LPCONTEXT ThreadContext
    )
{
    STATUS status;
    SIZE_T rspValue, read;

    switch (Instruction.mnemonic)
    {
    case ZYDIS_MNEMONIC_RET:
        // Get the top of the stack and put it in RIP
        if (!ReadProcessMemory(
            gExeFile.ProcessHandle, 
#ifdef _WIN64
            (LPVOID)ThreadContext->Rsp, 
#else
            (LPVOID)ThreadContext->Esp, 
#endif
            &rspValue, 
            sizeof(rspValue),
            &read
        ))
        {
            LOG("[ERROR] ReadProcessMemory failed: %d\n", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }

#ifdef _WIN64
        ThreadContext->Rip = rspValue;
        ThreadContext->Rsp += (SIZE_T)8;
#else
        ThreadContext->Eip = rspValue;
        ThreadContext->Esp += (SIZE_T)4;
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