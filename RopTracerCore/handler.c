#include "handler.h"

#define RTR_DISASM_JUMPBACK_SIZE            0x64

DWORD RtrValidateRetHandler(
    _In_ const PCONTEXT ThreadContext,
    _In_ const LPDEBUG_EVENT TraceEv
    )
{
    UNREFERENCED_PARAMETER(TraceEv);

    DWORD returnValue = DBG_CONTINUE;

    SIZE_T rspValue, read;
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
        returnValue = STATUS_RTR_INTERNAL_ERROR;
        goto cleanup_and_exit;
    }

#ifdef _WIN64
    LOG("[TRACER] 0x%016llx - returns to -> 0x%016llx\n", (SIZE_T)TraceEv->u.Exception.ExceptionRecord.ExceptionAddress, rspValue);
#else
    LOG("[TRACER] 0x%08lx - returns to -> 0x%08lx\n", (SIZE_T)TraceEv->u.Exception.ExceptionRecord.ExceptionAddress, rspValue);
#endif
    SIZE_T originalRspValue = rspValue;
    rspValue -= RTR_DISASM_JUMPBACK_SIZE;

    BYTE codeBuffer[RTR_DISASM_JUMPBACK_SIZE];
    // Get the top of the stack and put it in RIP
    if (!ReadProcessMemory(
        gExeFile.ProcessHandle,
        (LPVOID)rspValue,
        codeBuffer,
        sizeof(codeBuffer),
        &read
    ))
    {
        LOG("[ERROR] ReadProcessMemory failed: %d\n", GetLastError());
        returnValue = STATUS_RTR_INTERNAL_ERROR;
        goto cleanup_and_exit;
    }

    // Initialize decoder context
    ZydisDecoder decoder;
#ifdef _WIN64
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#else
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#endif
    // Initialize formatter
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    DWORD status;

    SIZE_T runtime_address;
    SIZE_T offset;

    SIZE_T codeBytesRead = sizeof(codeBuffer);
    SIZE_T length;

    // Loop over the instructions replace RET instructions with INT3
    runtime_address = rspValue;
    offset = 0;
    // Length to decode
    length = codeBytesRead;
    ZydisDecodedInstruction instruction;

    while (offset < length)
    {
        status = ZydisDecoderDecodeBuffer(
            &decoder,
            (PVOID)(codeBuffer + offset),
            length - offset,
            0,
            &instruction);

        if (runtime_address + instruction.length == originalRspValue)
        {
            // Print current instruction pointer.
#ifdef _WIN64
            LOG("[DISASM] 0x%016llx   ", runtime_address);
#else
            LOG("[DISASM] 0x%08lx   ", runtime_address);
#endif

            // Format & print the binary instruction structure to human readable format
            char mnemonicBuffer[256];
            ZydisFormatterFormatInstruction(&formatter, &instruction, mnemonicBuffer, sizeof(mnemonicBuffer));
            LOG("%s\n\n", mnemonicBuffer);

            if (instruction.mnemonic != ZYDIS_MNEMONIC_CALL)
            {
                LOG("[TRACER] ROP Chain Detected. Aborting application.\n");
                returnValue = STATUS_RTR_ROP_CHAIN_DETECTED;
                goto cleanup_and_exit;
            }
        }

        runtime_address += instruction.length;
        offset += instruction.length;
    }

cleanup_and_exit:
    return returnValue;
}

DWORD
RtrBreakpointHandler(
    _In_ const LPDEBUG_EVENT TraceEv
    )
{
    DWORD returnValue = DBG_CONTINUE;
    HANDLE hThread = NULL;
    CONTEXT threadContext;
    threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

    hThread = OpenThread(
        THREAD_ALL_ACCESS,
        FALSE,
        TraceEv->dwThreadId
    );
    if (NULL == hThread)
    {
        LOG("[ERROR] OpenThread failed: %d\n", GetLastError());
        returnValue = STATUS_RTR_INTERNAL_ERROR;
        goto cleanup_and_exit;
    }

    if (!GetThreadContext(hThread, &threadContext))
    {
        LOG("[ERROR] GetThreadContext failed: %d\n", GetLastError());
        returnValue = STATUS_RTR_INTERNAL_ERROR;
        goto cleanup_and_exit;
    }

    BYTE ret = RTR_RET_INSTRUCTION;
    SIZE_T written;
    if (!WriteProcessMemory(
        gExeFile.ProcessHandle,
        (LPVOID)TraceEv->u.Exception.ExceptionRecord.ExceptionAddress,
        &ret,
        1,
        &written
    ))
    {
        LOG("[ERROR] WriteProcessMemory failed: %d\n", GetLastError());
        returnValue = STATUS_RTR_INTERNAL_ERROR;
        goto cleanup_and_exit;
    }

#ifdef _WIN64
    threadContext.Rip -= 1;
#else
    threadContext.Eip -= 1;
#endif
    threadContext.EFlags |= TRAP_FLAG_MASK;
    gExeFile.LastAddr = (SIZE_T)TraceEv->u.Exception.ExceptionRecord.ExceptionAddress;

    returnValue = RtrValidateRetHandler(&threadContext, TraceEv);

    if (!FlushInstructionCache(gExeFile.ProcessHandle, NULL, 0))
    {
        LOG("[ERROR] FlushInstructionCache failed: %d\n", GetLastError());
    }

    if (!SetThreadContext(hThread, &threadContext))
    {
        LOG("[ERROR] SetThreadContext failed: %d\n", GetLastError());
        returnValue = STATUS_RTR_INTERNAL_ERROR;
        goto cleanup_and_exit;
    }

cleanup_and_exit:
    if (NULL != hThread)
    {
        CloseHandle(hThread);
    }

    return returnValue;
}

DWORD
RtrSingleStepHandler(
    _In_ const LPDEBUG_EVENT TraceEv
)
{
    DWORD returnValue = DBG_CONTINUE;
    HANDLE hThread = NULL;
    CONTEXT threadContext;
    threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

    hThread = OpenThread(
        THREAD_ALL_ACCESS,
        FALSE,
        TraceEv->dwThreadId
    );
    if (NULL == hThread)
    {
        LOG("[ERROR] OpenThread failed: %d\n", GetLastError());
        returnValue = STATUS_RTR_INTERNAL_ERROR;
        goto cleanup_and_exit;
    }

    if (!GetThreadContext(hThread, &threadContext))
    {
        LOG("[ERROR] GetThreadContext failed: %d\n", GetLastError());
        returnValue = STATUS_RTR_INTERNAL_ERROR;
        goto cleanup_and_exit;
    }

    SIZE_T written;
    BYTE breakpoint = RTR_INT3_INSTRUCTION; // INT3
    if (!WriteProcessMemory(
        gExeFile.ProcessHandle, 
        (LPVOID)gExeFile.LastAddr,
        (LPVOID)&breakpoint, 
        1,
        &written))
    {
        LOG("[ERROR] WriteProcessMemory failed: %d\n", GetLastError());
        returnValue = STATUS_RTR_INTERNAL_ERROR;
        goto cleanup_and_exit;
    }

    threadContext.EFlags &= ~TRAP_FLAG_MASK;

    if (!FlushInstructionCache(gExeFile.ProcessHandle, NULL, 0))
    {
        LOG("[ERROR] FlushInstructionCache failed: %d\n", GetLastError());
    }

    if (!SetThreadContext(hThread, &threadContext))
    {
        LOG("[ERROR] SetThreadContext failed: %d\n", GetLastError());
        returnValue = STATUS_RTR_INTERNAL_ERROR;
        goto cleanup_and_exit;
    }

cleanup_and_exit:
    if (NULL != hThread)
    {
        CloseHandle(hThread);
    }

    return returnValue;
}