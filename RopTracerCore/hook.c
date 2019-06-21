#include "hook.h"
#include "Zydis\DecoderTypes.h"

STATUS 
RtrFreeHooks(
    _In_ VOID
    )
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
            LOG("[ERROR] VirtualFree failed: %d\n", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }

        list = list->Flink;
    }

    return STATUS_SUCCESS;
}

STATUS RtrUnhookRegion(
    _In_ SIZE_T Address, 
    _In_ DWORD Size
    )
{
    LIST_ENTRY *list;

    list = gExeFile.InstructionPatchList.Flink;
    while (list != &gExeFile.InstructionPatchList)
    {
        PRET_PATCH pRetPatchEntry = CONTAINING_RECORD(list, RET_PATCH, Link);

        if (pRetPatchEntry->Address < Address || pRetPatchEntry->Address > (Address + Size))
        {
            goto _continue;
        }

        pRetPatchEntry->Disabled = TRUE;
        RemoveEntryList(list);
        list = list->Blink;

        SIZE_T written;
        if (!WriteProcessMemory(
            gExeFile.ProcessHandle,
            (LPVOID)pRetPatchEntry->Address,
            &pRetPatchEntry->OriginalByte,
            1,
            &written
        ))
        {
            LOG("[ERROR] WriteProcessMemory failed: %d\n", GetLastError());
        }

        if (!VirtualFree(pRetPatchEntry, 0, MEM_RELEASE))
        {
            LOG("[ERROR] VirtualFree failed: %d\n", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }

    _continue:
        list = list->Flink;
    }

    return STATUS_SUCCESS;
}

STATUS 
RtrHookModule(
    _In_ SIZE_T ImageBase,
    _In_ HANDLE FileHandle
    )
{
    STATUS status = STATUS_SUCCESS;
    LPVOID fileBase = NULL;
    HANDLE hMapping = NULL;

    hMapping = CreateFileMapping(FileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (NULL == hMapping)
    {
        LOG("[ERROR] CreateFileMapping failed: %d\n", GetLastError());
        status = STATUS_UNSUCCESSFUL;
        goto cleanup_and_exit;
    }

    fileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (NULL == fileBase)
    {
        LOG("[ERROR] MapViewOfFile failed: %d\n", GetLastError());
        status = STATUS_UNSUCCESSFUL;
        goto cleanup_and_exit;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBase;
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
                LOG("[ERROR] RtrHookRegion failed: 0x%08x\n", status);
                status = STATUS_UNSUCCESSFUL;
                goto cleanup_and_exit;
            }
        }
        else
        {
            continue;
        }
    }

cleanup_and_exit:
    if (NULL != hMapping)
    {
        CloseHandle(hMapping);
    }

    if (NULL != fileBase)
    {
        UnmapViewOfFile(fileBase);
    }

    return status;
}

STATUS 
RtrUnhookModule(
    _In_ SIZE_T ImageBase,
    _In_ HANDLE FileHandle
    )
{
    STATUS status = STATUS_SUCCESS;
    LPVOID fileBase = NULL;
    HANDLE hMapping = NULL;

    hMapping = CreateFileMapping(FileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (NULL == hMapping)
    {
        LOG("[ERROR] CreateFileMapping failed: %d\n", GetLastError());
        status = STATUS_UNSUCCESSFUL;
        goto cleanup_and_exit;
    }

    fileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (NULL == fileBase)
    {
        LOG("[ERROR] MapViewOfFile failed: %d\n", GetLastError());
        status = STATUS_UNSUCCESSFUL;
        goto cleanup_and_exit;
    }

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
                LOG("[ERROR] RtrUnhookRegion failed: 0x%08x\n", status);
                status = STATUS_UNSUCCESSFUL;
                goto cleanup_and_exit;
            }
            else
            {
                continue;
            }
        }
    }

cleanup_and_exit:
    if (NULL != hMapping)
    {
        CloseHandle(hMapping);
    }

    if (NULL != fileBase)
    {
        UnmapViewOfFile(fileBase);
    }

    return status;
}

STATUS 
RtrHookRegion(
    _In_ SIZE_T Address, 
    _In_ DWORD Size
    )
{
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

    BYTE codeBuffer[PAGE_SIZE];
    SIZE_T codeBytesRead;
    SIZE_T length;

read_again:
    if (!ReadProcessMemory(
        gExeFile.ProcessHandle, 
        (LPCVOID)Address, 
        codeBuffer, 
        Size <= PAGE_SIZE ? Size : PAGE_SIZE, 
        &codeBytesRead
    ))
    {
        LOG("[ERROR] ReadProcessMemory failed: %d\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    // Loop over the instructions replace RET instructions with INT3
    runtime_address = Address;
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

            /// Print current instruction pointer.
            /// LOG("[DISASM] 0x%016llx   ", runtime_address);
            /// 
            /// // Format & print the binary instruction structure to human readable format
            /// char mnemonicBuffer[256];
            /// ZydisFormatterFormatInstruction(&formatter, &instruction, mnemonicBuffer, sizeof(mnemonicBuffer));
            /// LOG("%s\n", mnemonicBuffer);

            // Allocate and initialize a RET patch structure for the list
            PRET_PATCH pRetPatchEntry = VirtualAlloc(NULL, sizeof(RET_PATCH), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (NULL == pRetPatchEntry)
            {
                LOG("[ERROR] VirtualAlloc failed: 0x%08x\n", GetLastError());
                return STATUS_UNSUCCESSFUL;
            }

            pRetPatchEntry->Address = runtime_address;
            pRetPatchEntry->Disabled = FALSE;
            pRetPatchEntry->Instruction = instruction;
            pRetPatchEntry->OriginalByte = *(codeBuffer + offset);

            // Patch RET with a INT3
            SIZE_T written;
            BYTE breakpoint = RTR_INT3_INSTRUCTION; // INT3
            if (!WriteProcessMemory(
                gExeFile.ProcessHandle,
                (LPVOID)runtime_address,
                &breakpoint,
                1,
                &written
            ))
            {
                LOG("[ERROR] WriteProcessMemory failed: %d\n", GetLastError());
            }

            gExeFile.PatchCount++;
            InsertTailList(&gExeFile.InstructionPatchList, &pRetPatchEntry->Link);
        }

        offset += instruction.length;
        runtime_address += instruction.length;
    }

    if (Size - (DWORD)codeBytesRead > 0)
    {
        Size = Size - (DWORD)codeBytesRead;
        Address = Address + codeBytesRead;
        goto read_again;
    }

    return STATUS_SUCCESS;
}