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
    STATUS status = STATUS_SUCCESS;
  
    if (DLL_PROCESS_ATTACH == _Reason)
    {
        // Suspends all process threads
        status = RtrSuspendThreads();
        if (!SUCCEEDED(status))
        {
            printf("[ERROR] RtrSuspendsThreads failed: 0x%08x\n", status);
        }
        
        // Initialize gExeFile list head for RET patches
        InitializeListHead(&gExeFile.InstructionPatchList);

        // Register critical exception handler
        AddVectoredExceptionHandler(1, RtrBreakpointHandler);

        // Get current .exe image base address
        HMODULE hCurrentModule = GetModuleHandle(NULL);
        if (NULL == hCurrentModule)
        {
            MessageBox(NULL, "GetModuleHandle failed. Aborting", "RopTracerDll.dll", MB_ICONERROR);
        }
        gExeFile.ImageBase = (QWORD)hCurrentModule;

        // Hook RET instructions from all executable sections
        status = RtrHookModule(gExeFile.ImageBase);
        if (!SUCCEEDED(status))
        {
           MessageBox(NULL, "RtrHookModule failed.", "RopTracerDll.dll", MB_ICONERROR);
        }

        _itoa_s(GetCurrentProcessId(), number, 20, 10);

        strcat_s(text, 256, "RopTracerDll.dll has been successfully injected in target with pid: ");
        strcat_s(text, 256, number);
        _itoa_s(GetCurrentProcessId(), number, 20, 16);
        strcat_s(text, 256, " (0x");
        strcat_s(text, 256, number);
        strcat_s(text, 256, ")");
        strcat_s(text, 256, ". Application protected against ROP Chain exploits!");

        MessageBox(NULL, text, "RopTracerDll.dll", MB_ICONINFORMATION);

        // Resume all threads
        status = RtrResumeThreads();
        if (!SUCCEEDED(status))
        {
            printf("[ERROR] RtrSuspendsThreads failed: 0x%08x\n", status);
        }
    }
    else if (DLL_PROCESS_DETACH == _Reason)
    {
        status = RtrFreeHooks();
        if (!SUCCEEDED(status))
        {
            MessageBox(NULL, "RtrFreeHooks failed.", "RopTracerDll.dll", MB_ICONERROR);
        }

        MessageBox(NULL, "DLL is detaching", "RopTracerDll.dll", MB_ICONINFORMATION);
    }

    return TRUE;
}
