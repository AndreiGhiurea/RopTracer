#include "hook.h"
#include "Zydis\DecoderTypes.h"

STATUS RtrHookModule(SIZE_T ImageBase)
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
                LOG("[ERROR] VirtualProtect failed: %d\n", GetLastError());
                return STATUS_UNSUCCESSFUL;
            }
            LOG("[INFO] Hooked section: %s. Current patch count: %d\n", pSectionHeader->Name, (int)gExeFile.PatchCount);
        }
        else
        {
            continue;
        }
    }

    return STATUS_SUCCESS;
}

STATUS RtrHookRegion(SIZE_T Address, DWORD Size)
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
        LOG("[ERROR] VirtualProtect failed: %d\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
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
            if (instruction.length != 1)
            {
                offset += instruction.length;
                runtime_address += instruction.length;
                continue;
            }

            // Patch RET with a INT3
            *((PBYTE)runtime_address) = 0xCC; // INT3

            gExeFile.PatchCount++;
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
        LOG("[ERROR] VirtualProtect failed: %d\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}