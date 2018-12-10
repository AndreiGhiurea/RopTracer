#include "hook.h"

STATUS RtrUnhookAddress(QWORD Address)
{
    LIST_ENTRY *list;
    DWORD oldPageRights = 0, newOldPageRights = 0;
    BOOL found = FALSE;

    list = gExeFile.RetPatchList.Flink;
    while (list != &gExeFile.RetPatchList && !found)
    {
        PRET_PATCH pRetPatch = CONTAINING_RECORD(list, RET_PATCH, Link);

        if (Address == pRetPatch->Address)
        {
            found = TRUE;
            BYTE instructionLength = pRetPatch->Instruction.length;

            // Modify section rights to read/write/execute
            if (!VirtualProtect(
                (LPVOID)(Address),
                instructionLength,
                PAGE_EXECUTE_READWRITE,
                &oldPageRights)
                )
            {
                MessageBox(NULL, "VirtualProtect failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
                return STATUS_UNSUCCESSFUL;
            }

            // Patch original instruction
            for (int i = 0; i < pRetPatch->Instruction.length; i++)
            {
                *((PBYTE)pRetPatch->Address + i) = pRetPatch->InstructionBytes[i];
                pRetPatch->Disabled = TRUE;
                RemoveEntryList(pRetPatch);
                if (!VirtualFree(pRetPatch, 0, MEM_RELEASE))
                {
                    MessageBox(NULL, "VirtualFree failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
                    return STATUS_UNSUCCESSFUL;
                }
            }

            // Restore old page rights
            if (!VirtualProtect(
                (LPVOID)(Address),
                instructionLength,
                oldPageRights,
                &newOldPageRights)
                )
            {
                MessageBox(NULL, "VirtualProtect failed", "RopTracerDll.dll", MB_ICONERROR);
                return STATUS_UNSUCCESSFUL;
            }
        }

    _continue:
        list = list->Flink;
    }

    if (!found)
    {
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

STATUS RtrHookAddress(QWORD Address)
{
    DWORD oldPageRights = 0, newOldPageRights = 0;

    // Initialize decoder context
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    // Initialize formatter
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    // Loop over the instructions from entry point and replace RET instructions with INT3
    ZyanUPointer runtime_address = Address;
    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;

    if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
        &decoder,
        (PVOID)(Address),
        0,
        &instruction))
        )
    {
        if (ZYDIS_MNEMONIC_RET == instruction.mnemonic)
        {
            // Print current instruction pointer.
            printf("[DISASM] 0x%016llx   ", runtime_address);

            // Format & print the binary instruction structure to human readable format
            char buffer[256];
            ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer),
                runtime_address);
            printf("%s\n", buffer);

            // Modify section rights to read/write/execute
            if (!VirtualProtect(
                (LPVOID)(Address),
                instruction.length,
                PAGE_EXECUTE_READWRITE,
                &oldPageRights)
                )
            {
                MessageBox(NULL, "VirtualProtect failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
                return STATUS_UNSUCCESSFUL;
            }

            // Allocate and initialize a RET patch structure for the list
            PRET_PATCH retPatchEntry = VirtualAlloc(NULL, sizeof(RET_PATCH), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (NULL == retPatchEntry)
            {
                MessageBox(NULL, "VirtualAlloc failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
                return STATUS_UNSUCCESSFUL;
            }

            retPatchEntry->Address = runtime_address;
            retPatchEntry->Disabled = FALSE;
            retPatchEntry->Instruction = instruction;

            // Patch RET with a INT3
            retPatchEntry->InstructionBytes[0] = *(PBYTE)runtime_address;
            *((PBYTE)runtime_address) = 0xCC; // INT3
            for (int i = 1; i < instruction.length; i++)
            {
                retPatchEntry->InstructionBytes[i] = *((PBYTE)runtime_address + i);
                *((PBYTE)runtime_address + i) = 0x90; // NOP
            }

            InsertTailList(&gExeFile.RetPatchList, &retPatchEntry->Link);
        }

        // Restore old page rights
        if (!VirtualProtect(
            (LPVOID)(Address),
            instruction.length,
            oldPageRights,
            &newOldPageRights)
            )
        {
            MessageBox(NULL, "VirtualProtect failed", "RopTracerDll.dll", MB_ICONERROR);
            return STATUS_UNSUCCESSFUL;
        }
    }

    return STATUS_SUCCESS;
}

STATUS RtrUnhookRegion(QWORD Address, DWORD Size)
{
    LIST_ENTRY *list;
    DWORD oldPageRights = 0, newOldPageRights = 0;

    // Modify section rights to read/write/execute
    if (!VirtualProtect(
        (LPVOID)(Address),
        Size,
        PAGE_EXECUTE_READWRITE,
        &oldPageRights)
        )
    {
        MessageBox(NULL, "VirtualProtect failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
        return STATUS_UNSUCCESSFUL;
    }

    list = gExeFile.RetPatchList.Flink;
    while (list != &gExeFile.RetPatchList)
    {
        PRET_PATCH pRetPatch = CONTAINING_RECORD(list, RET_PATCH, Link);

        if (pRetPatch->Address < Address || pRetPatch->Address >(Address + Size))
        {
            goto _continue;
        }

        // Patch original instruction
        for (int i = 0; i < pRetPatch->Instruction.length; i++)
        {
            *((PBYTE)pRetPatch->Address + i) = pRetPatch->InstructionBytes[i];
            pRetPatch->Disabled = TRUE;
            RemoveEntryList(pRetPatch);
            if (!VirtualFree(pRetPatch, 0, MEM_RELEASE))
            {
                MessageBox(NULL, "VirtualFree failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
                return STATUS_UNSUCCESSFUL;
            }
        }

    _continue:
        list = list->Flink;
    }

    // Restore old page rights
    if (!VirtualProtect(
        (LPVOID)(Address),
        Size,
        oldPageRights,
        &newOldPageRights)
        )
    {
        MessageBox(NULL, "VirtualProtect failed", "RopTracerDll.dll", MB_ICONERROR);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

STATUS RtrHookRegion(QWORD Address, DWORD Size)
{
    DWORD oldPageRights = 0, newOldPageRights = 0;

    // Modify section rights to read/write/execute
    if (!VirtualProtect(
        (LPVOID)(Address),
        Size,
        PAGE_EXECUTE_READWRITE,
        &oldPageRights)
        )
    {
        MessageBox(NULL, "VirtualProtect failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
        return STATUS_UNSUCCESSFUL;
    }

    // Initialize decoder context
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    // Initialize formatter
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    // Loop over the instructions from entry point and replace RET instructions with INT3
    ZyanUPointer runtime_address = Address;
    ZyanUSize offset = 0;
    // Length to decode
    const ZyanUSize length = Size;
    ZydisDecodedInstruction instruction;

    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
        &decoder,
        (PVOID)(Address + offset),
        length - offset,
        &instruction))
        )
    {
        if (ZYDIS_MNEMONIC_RET == instruction.mnemonic)
        {
            // Print current instruction pointer.
            printf("[DISASM] 0x%016llx   ", runtime_address);

            // Format & print the binary instruction structure to human readable format
            char buffer[256];
            ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer),
                runtime_address);
            printf("%s\n", buffer);
            // Allocate and initialize a RET patch structure for the list
            PRET_PATCH retPatchEntry = VirtualAlloc(NULL, sizeof(RET_PATCH), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (NULL == retPatchEntry)
            {
                MessageBox(NULL, "VirtualAlloc failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
                return STATUS_UNSUCCESSFUL;
            }

            retPatchEntry->Address = runtime_address;
            retPatchEntry->Disabled = FALSE;
            retPatchEntry->Instruction = instruction;

            // Patch RET with a INT3
            retPatchEntry->InstructionBytes[0] = *(PBYTE)runtime_address;
            *((PBYTE)runtime_address) = 0xCC; // INT3
            for (int i = 1; i < instruction.length; i++)
            {
                retPatchEntry->InstructionBytes[i] = *((PBYTE)runtime_address + i);
                *((PBYTE)runtime_address + i) = 0x90; // NOP
            }

            InsertTailList(&gExeFile.RetPatchList, &retPatchEntry->Link);
        }

        offset += instruction.length;
        runtime_address += instruction.length;
    }

    // Restore old page rights
    if (!VirtualProtect(
        (LPVOID)(Address),
        Size,
        oldPageRights,
        &newOldPageRights)
        )
    {
        MessageBox(NULL, "VirtualProtect failed", "RopTracerDll.dll", MB_ICONERROR);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}