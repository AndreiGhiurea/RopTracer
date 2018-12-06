#include "utils.h"
#include "handler.h"

BOOL
APIENTRY DllMain(
    _In_        void*           _DllHandle,
    _In_        unsigned long   _Reason,
    _In_opt_    void*           _Reserved
    )
{
    UNREFERENCED_PARAMETER(_DllHandle);
    UNREFERENCED_PARAMETER(_Reserved);

    CHAR    text[256] = { 0 };
    CHAR    number[20] = { 0 };
    DWORD   oldPageRights = 0;
    PIMAGE_SECTION_HEADER pTextSection = NULL;
  
    if (DLL_PROCESS_ATTACH == _Reason)
    {
        // Initialize gExeFile list head for RET patches
        InitializeListHead(&gExeFile.RetPatchList);

        // Register critical exception handler
        AddVectoredExceptionHandler(1, BreakpointHandler);

        _itoa_s(GetCurrentProcessId(), number, 20, 10);

        strcat_s(text, 256, "RopTracerDll.dll has been successfully injected in target with pid: ");
        strcat_s(text, 256, number);
        _itoa_s(GetCurrentProcessId(), number, 20, 16);
        strcat_s(text, 256, " (0x");
        strcat_s(text, 256, number);
        strcat_s(text, 256, ")");

        // MessageBox(NULL, text, "RopTracerDll.dll", MB_ICONINFORMATION);

        // Get current .exe image base address
        HMODULE hCurrentModule = GetModuleHandle(NULL);
        if (NULL == hCurrentModule)
        {
            MessageBox(NULL, "GetModuleHandle failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
        }
        gExeFile.ImageBase = (QWORD)hCurrentModule;

        // Parse the PE file in memory to find the entry point and .text section
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)gExeFile.ImageBase;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)pDosHeader + pDosHeader->e_lfanew);
        PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeaders->FileHeader;

        gExeFile.EntryPointRva = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
        gExeFile.EntryPoint = gExeFile.ImageBase + gExeFile.EntryPointRva;

        PIMAGE_SECTION_HEADER pSectionHeader;
        for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
        {
            pSectionHeader = (PIMAGE_SECTION_HEADER)((PCHAR)pFileHeader + sizeof(IMAGE_FILE_HEADER) + pFileHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * i);
            if (0 == strcmp(".text", (const char*)pSectionHeader->Name))
            {
                pTextSection = pSectionHeader;
                break;
            }
        }

        if (NULL == pTextSection)
        {
            MessageBox(NULL, "Couldn't find .text section. Aborting", "RopTracerDll.dll", MB_ICONERROR);
            return FALSE;
        }

        printf("[INFO] ImageBase: 0x%016llx\n", gExeFile.ImageBase);
        printf("[INFP] EntryPointRva: 0x%08lx\n", gExeFile.EntryPointRva);
        printf("[INFO] EntryPoint: 0x%016llx\n", gExeFile.EntryPoint);
        printf("[INFO] .textSection: 0x%016llx\n", gExeFile.ImageBase + pTextSection->VirtualAddress);

        // Modify .text section right to read/write/execute from read/execute
        if (!VirtualProtect(
            (LPVOID)(gExeFile.ImageBase + pTextSection->VirtualAddress),
            pTextSection->Misc.VirtualSize,
            PAGE_EXECUTE_READWRITE,
            &oldPageRights)
            )
        {
            MessageBox(NULL, "VirtualProtect failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
            return FALSE;
        }

        // Initialize decoder context
        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
        // Initialize formatter
        ZydisFormatter formatter;
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

        // Loop over the instructions from entry point and replace RET instructions with INT3
        ZyanUPointer runtime_address = gExeFile.EntryPoint;
        ZyanUSize offset = 0;
        // Length to decode
        const ZyanUSize length = pTextSection->Misc.VirtualSize;
        ZydisDecodedInstruction instruction;

        while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
            &decoder, 
            (PVOID)(gExeFile.EntryPoint + offset), 
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
    }
    else if (DLL_PROCESS_DETACH == _Reason)
    {
        MessageBox(NULL, "DLL is detaching", "RopTracerDll.dll", MB_ICONINFORMATION);

        // Restore .text section rights before detaching the dll
        if (pTextSection != NULL && oldPageRights != 0)
        {
            DWORD newOldPageRights;
            if (!VirtualProtect(
                (LPVOID)(gExeFile.ImageBase + pTextSection->VirtualAddress),
                pTextSection->Misc.VirtualSize,
                oldPageRights,
                &newOldPageRights)
                )
            {
                MessageBox(NULL, "VirtualProtect failed", "RopTracerDll.dll", MB_ICONERROR);
            }
        }
    }

    return TRUE;
}
