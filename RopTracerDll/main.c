#include "utils.h"
#include "handler.h"
#include "hook.h"

BOOL APIENTRY
DllMain(
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
    STATUS status = NULL;
  
    if (DLL_PROCESS_ATTACH == _Reason)
    {
        // Initialize gExeFile list head for RET patches
        InitializeListHead(&gExeFile.RetPatchList);

        // Register critical exception handler
        // AddVectoredExceptionHandler(1, BreakpointHandler);

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

        // Hook RET instructions from .text section
        DWORD oldPageRights;
        status = RtrHookRegion(gExeFile.ImageBase + pTextSection->VirtualAddress, pTextSection->Misc.VirtualSize, &oldPageRights);
        if (!SUCCEEDED(status))
        {
            printf("[ERROR] RtrHookRegion failed\n");
        }
    }
    else if (DLL_PROCESS_DETACH == _Reason)
    {

        status = RtrUnhookRegion(gExeFile.ImageBase + pTextSection->VirtualAddress, pTextSection->Misc.VirtualSize, oldPageRights);
        if (!SUCCEEDED(status))
        {
            printf("[ERROR] RtrUnhookRegion failed\n");
        }
        
        MessageBox(NULL, "DLL is detaching", "RopTracerDll.dll", MB_ICONINFORMATION);
    }

    return TRUE;
}
