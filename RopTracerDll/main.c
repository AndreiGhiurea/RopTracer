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
#ifdef _DEBUG
        AllocConsole();
        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
#endif

        // Suspends all process threads
        status = RtrSuspendThreads();
        if (!SUCCEEDED(status))
        {
            LOG("[ERROR] RtrSuspendsThreads failed: 0x%08x\n", status);
        }
        
        // Register critical exception handler
        AddVectoredExceptionHandler(1, RtrBreakpointHandler);

        // Get current .exe image base address
        HMODULE hCurrentModule = GetModuleHandle(NULL);
        if (NULL == hCurrentModule)
        {
            LOG("[ERROR] GetModuleHandle failed: %d\n", GetLastError());
        }

        // Hook RET instructions from all executable sections
        status = RtrHookModule((SIZE_T)hCurrentModule);
        if (!SUCCEEDED(status))
        {
           LOG("[ERROR] RtrHookModule failed: %d\n", GetLastError());
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
            LOG("[ERROR] RtrSuspendsThreads failed: 0x%08x\n", status);
        }
    }
    else if (DLL_PROCESS_DETACH == _Reason)
    {
        LOG("[INFO] DLL is detaching");
    }

    return TRUE;
}
