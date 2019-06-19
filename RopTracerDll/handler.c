#include "handler.h"
#include "emu.h"

LONG WINAPI
RtrBreakpointHandler(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
    LONG returnValue = EXCEPTION_EXECUTE_HANDLER;
    DWORD exceptioncode;

    exceptioncode = ExceptionInfo->ExceptionRecord->ExceptionCode;

    switch (exceptioncode)
    {
    case EXCEPTION_BREAKPOINT:
#ifdef _WIN64
        LOG("[TRACER] 0x%016llx - returns to -> 0x%016llx\n", (SIZE_T)ExceptionInfo->ExceptionRecord->ExceptionAddress, *(PSIZE_T)ExceptionInfo->ContextRecord->Rsp);
#else
        LOG("[TRACER] 0x%08lx - returns to -> 0x%08lx\n", (SIZE_T)ExceptionInfo->ExceptionRecord->ExceptionAddress, *(PSIZE_T)ExceptionInfo->ContextRecord->Esp);
#endif

#ifdef _WIN64
        SIZE_T originalRspValue = *(PSIZE_T)ExceptionInfo->ContextRecord->Rsp;
#else
        SIZE_T originalRspValue = *(PSIZE_T)ExceptionInfo->ContextRecord->Esp;
#endif // _WIN64
        SIZE_T rspValue = originalRspValue;
        rspValue -= 0x64;

        PBYTE codeBuffer = (PBYTE)rspValue;

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

        SIZE_T codeBytesRead = 0x64;
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
                    // Suspends all process threads
                    status = RtrSuspendThreads();
                    if (!SUCCEEDED(status))
                    {
                        LOG("[ERROR] RtrSuspendsThreads failed: 0x%08x\n", status);
                    }

                    LOG("[TRACER] ROP Chain Detected. Aborting application.\n");
                    MessageBox(NULL, "ROP Chain Detected. Aborting execution!", "RopTracer", MB_ICONERROR);
                    ExitProcess((UINT)1);
                }
            }

            runtime_address += instruction.length;
            offset += instruction.length;
        }

        status = RtrEmulateInstruction(instruction, ExceptionInfo);
        if (!SUCCESS(status))
        {
            LOG("[ERROR] RtrEmulateInstruction failed: 0x%08x\n", status);
        }

        returnValue = EXCEPTION_CONTINUE_EXECUTION;
        return returnValue;
    case EXCEPTION_SINGLE_STEP:
        LOG("[INFO] Single Stepping\n");
        return EXCEPTION_CONTINUE_EXECUTION;
        break;
    default:
        return EXCEPTION_CONTINUE_SEARCH;
        break;
    }
}
