#include "hook.h"
#include "Zydis\DecoderTypes.h"

STATUS RtrFreeHooks(VOID)
{
    LIST_ENTRY *list;

    list = gExeFile.InstructionPatchList.Flink;
    while (list != &gExeFile.InstructionPatchList)
    {
        PRET_PATCH pRetPatch = CONTAINING_RECORD(list, RET_PATCH, Link);

        pRetPatch->Disabled = TRUE;
        RemoveEntryList(list);
        list = list->Blink;

        if (!VirtualFree(pRetPatch, 0, MEM_RELEASE))
        {
            MessageBox(NULL, "VirtualFree failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
            return STATUS_UNSUCCESSFUL;
        }

        list = list->Flink;
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

    list = gExeFile.InstructionPatchList.Flink;
    while (list != &gExeFile.InstructionPatchList)
    {
        PRET_PATCH pRetPatch = CONTAINING_RECORD(list, RET_PATCH, Link);

        if (pRetPatch->Address < Address || pRetPatch->Address >(Address + Size))
        {
            goto _continue;
        }

        pRetPatch->Disabled = TRUE;
        RemoveEntryList(list);
        list = list->Blink;

        // Patch original instruction
        for (int i = 0; i < pRetPatch->Instruction.length; i++)
        {
            *((PBYTE)pRetPatch->Address + i) = pRetPatch->InstructionBytes[i];
        }

        if (!VirtualFree(pRetPatch, 0, MEM_RELEASE))
        {
            MessageBox(NULL, "VirtualFree failed", "RopTracerDll.dll", MB_ICONERROR);
            return STATUS_UNSUCCESSFUL;
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

STATUS RtrHookModule(QWORD ImageBase)
{
    STATUS status;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeaders->FileHeader;

    PIMAGE_SECTION_HEADER pSectionHeader;
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        pSectionHeader = (PIMAGE_SECTION_HEADER)((PCHAR)pFileHeader + sizeof(IMAGE_FILE_HEADER) + pFileHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * i);
        if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            status = RtrHookRegion(ImageBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize);
            if (!SUCCEEDED(status))
            {
                MessageBox(NULL, "RtrHookRegion failed", "RopTracerDll.dll", MB_ICONERROR);
                return STATUS_UNSUCCESSFUL;
            }
        }
        else
        {
            continue;
        }
    }

    return STATUS_SUCCESS;
}

STATUS RtrUnhookModule(QWORD ImageBase)
{
    STATUS status;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeaders->FileHeader;

    PIMAGE_SECTION_HEADER pSectionHeader;
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        pSectionHeader = (PIMAGE_SECTION_HEADER)((PCHAR)pFileHeader + sizeof(IMAGE_FILE_HEADER) + pFileHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * i);
        if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            status = RtrUnhookRegion(ImageBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize);
            if (!SUCCEEDED(status))
            {
                MessageBox(NULL, "RtrHookRegion failed", "RopTracerDll.dll", MB_ICONERROR);
                return STATUS_UNSUCCESSFUL;
            }
            else
            {
                continue;;
            }
        }
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
    DWORD status;
    SIZE_T runtime_address;
    SIZE_T offset;
    SIZE_T length;

    // Loop over the instructions replace RET instructions with INT3
    runtime_address = Address;
    offset = 0;
    // Length to decode
    length = Size;
    ZydisDecodedInstruction instruction;
    
    while (offset < length)
    {
        status = ZydisDecoderDecodeBuffer(
            &decoder,
            (PVOID)(Address + offset),
            length - offset,
            0,
            &instruction);

        if (ZYDIS_MNEMONIC_INVALID == instruction.mnemonic)
        {
            offset += instruction.length;
            runtime_address += instruction.length;
            continue;
        }

        if (ZYDIS_MNEMONIC_RET == instruction.mnemonic)
        {
            // Special case
            if (instruction.length != 1
//                instruction.length == 3 &&
//                *((PBYTE)runtime_address) == 0xC2 &&
//                *((PBYTE)runtime_address + 1) == 0x00 &&
//                *((PBYTE)runtime_address + 2) == 0x00
                )
            {
                offset += instruction.length;
                runtime_address += instruction.length;
                continue;
            }

            // Allocate and initialize a RET patch structure for the list
            PRET_PATCH instructionPatchEntry = VirtualAlloc(NULL, sizeof(RET_PATCH), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (NULL == instructionPatchEntry)
            {
                MessageBox(NULL, "VirtualAlloc failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
                return STATUS_UNSUCCESSFUL;
            }

            instructionPatchEntry->Address = runtime_address;
            instructionPatchEntry->Disabled = FALSE;
            instructionPatchEntry->Instruction = instruction;

            for (int i = 0; i < instruction.length; i++)
            {
                instructionPatchEntry->InstructionBytes[i] = *((PBYTE)runtime_address + i);
            }

            InsertTailList(&gExeFile.InstructionPatchList, &instructionPatchEntry->Link);

            // Patch RET with a INT3
            *((PBYTE)runtime_address) = 0xCC; // INT3
            for (int i = 1; i < instruction.length; i++)
            {
                *((PBYTE)runtime_address + i) = 0x90; // NOP
            }
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