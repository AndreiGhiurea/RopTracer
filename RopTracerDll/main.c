#include "utils.h"
#include <Zydis/Zydis.h>

EXE_FILE gExeFile;

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
        _itoa_s(GetCurrentProcessId(), number, 20, 10);

        strcat_s(text, 256, "ROProtect.dll has been successfully injected in target with pid: ");
        strcat_s(text, 256, number);
        _itoa_s(GetCurrentProcessId(), number, 20, 16);
        strcat_s(text, 256, " (0x");
        strcat_s(text, 256, number);
        strcat_s(text, 256, ")");

        // MessageBox(NULL, text, "ROProtect.dll", MB_ICONINFORMATION);

        // Get current .exe image base address
        HMODULE hCurrentModule = GetModuleHandle(NULL);
        if (NULL == hCurrentModule)
        {
            MessageBox(NULL, "GetModuleHandle failed. Aborting", "ROProtect.dll", MB_ICONERROR);
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
            MessageBox(NULL, "Couldn't find .text section. Aborting", "ROProtect.dll", MB_ICONERROR);
            return FALSE;
        }

        printf("ImageBase: 0x%016llx\n", gExeFile.ImageBase);
        printf("EntryPointRva: 0x%08lx\n", gExeFile.EntryPointRva);
        printf("EntryPoint: 0x%016llx\n", gExeFile.EntryPoint);
        printf(".textSection: 0x%016llx\n", gExeFile.ImageBase + pTextSection->VirtualAddress);

        // Modify .text section right to read/write/execute from read/execute
        if (!VirtualProtect(
            (LPVOID)(gExeFile.ImageBase + pTextSection->VirtualAddress),
            pTextSection->Misc.VirtualSize,
            PAGE_EXECUTE_READWRITE,
            &oldPageRights)
            )
        {
            MessageBox(NULL, "VirtualProtect failed. Aborting", "ROProtect.dll", MB_ICONERROR);
            return FALSE;
        }

        // Initialize decoder context
        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
        // Initialize formatter
        ZydisFormatter formatter;
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

        // Loop over the instructions from entry point and replace RET instructions with INT3
        ZyanU64 runtime_address = gExeFile.EntryPoint;
        ZyanUSize offset = 0;
        // Length to decode
        const ZyanUSize length = pTextSection->Misc.VirtualSize;
        ZydisDecodedInstruction instruction;

        while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
            &decoder, 
            (PVOID)(gExeFile.EntryPoint + offset), length - offset,
            &instruction))
            )
        {
            if (ZYDIS_MNEMONIC_RET == instruction.mnemonic)
            {
                // Print current instruction pointer.
                printf("0x%016llx   ", runtime_address);

                // Format & print the binary instruction structure to human readable format
                char buffer[256];
                ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer),
                    runtime_address);
                printf("%s\n", buffer);
                
                // Patch RET with a INT3
                *((PBYTE)runtime_address) = 0xCC;
            }

            offset += instruction.length;
            runtime_address += instruction.length;
        }

        // Restore page rights after patching instructions
        DWORD newOldPageRights;
        if (!VirtualProtect(
            (LPVOID)(gExeFile.ImageBase + pTextSection->VirtualAddress),
            pTextSection->Misc.VirtualSize, 
            oldPageRights, 
            &newOldPageRights)
            )
        {
            MessageBox(NULL, "VirtualProtect failed", "ROProtect.dll", MB_ICONERROR);
            return FALSE;
        }
    }
    else if (DLL_PROCESS_DETACH == _Reason)
    {
        MessageBox(NULL, "DLL is detaching", "ROProtect.dll", MB_ICONINFORMATION);

        // Restore .text section rights if the dll is detaching before it was able to restore them normally
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
                MessageBox(NULL, "VirtualProtect failed", "ROProtect.dll", MB_ICONERROR);
            }
        }
    }

    return TRUE;
}