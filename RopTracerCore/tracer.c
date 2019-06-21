#include "tracer.h"
#include "callbacks.h"
#include "handler.h"

STATUS
RtrStartTrace(
    _In_ DWORD ProcessId
    )
{
    STATUS status = STATUS_SUCCESS;
    DEBUG_EVENT debugEv = { 0 };
    DWORD dwStatus;

    gExeFile.PatchCount = 0;
    gExeFile.ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    if (NULL == gExeFile.ProcessHandle)
    {
        LOG("[ERROR] OpenProcess failed: %d\n", GetLastError());
        status = STATUS_UNSUCCESSFUL;
        goto cleanup_and_exit;
    }

    if (!DebugActiveProcess(ProcessId))
    {
        LOG("[ERROR] DebugActiveProcess failed: %d\n", GetLastError());
        status = STATUS_UNSUCCESSFUL;
        goto cleanup_and_exit;
    }

    LOG("[TRACER] Attached to process successfully!\n");

    dwStatus = RtrEnterTraceLoop(&debugEv);

    if (dwStatus == STATUS_RTR_ROP_CHAIN_DETECTED)
    {
        MessageBox(NULL, "ROP Chain Detected. Aborting execution!", "RopTracer", MB_ICONSTOP);
        TerminateProcess(gExeFile.ProcessHandle, (UINT)STATUS_RTR_ROP_CHAIN_DETECTED);
    }
    else if (dwStatus == STATUS_RTR_INTERNAL_ERROR)
    {
        DebugActiveProcessStop(ProcessId);
    }

cleanup_and_exit:
    if (NULL != gExeFile.ProcessHandle)
    {
        CloseHandle(gExeFile.ProcessHandle);
    }

    return status;
}

DWORD
RtrEnterTraceLoop(
    _In_ const LPDEBUG_EVENT TraceEv
    )
{
    DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 

    for (;;)
    {
        // Wait for a debugging event to occur. The second parameter indicates
        // that the function does not return until a debugging event occurs. 
        WaitForDebugEvent(TraceEv, INFINITE);

        // Process the debugging event code. 
        switch (TraceEv->dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
            // Process the exception code. When handling 
            // exceptions, remember to set the continuation 
            // status parameter (dwContinueStatus). This value 
            // is used by the ContinueDebugEvent function. 

            switch (TraceEv->u.Exception.ExceptionRecord.ExceptionCode)
            {
            case EXCEPTION_ACCESS_VIOLATION:
                //LOG("Access Violation\n");
                dwContinueStatus = DBG_CONTINUE;
                break;

            case EXCEPTION_BREAKPOINT:
                dwContinueStatus = RtrBreakpointHandler(TraceEv);
                break;

            case EXCEPTION_DATATYPE_MISALIGNMENT:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                LOG("Data type misalignment\n");
                break;

            case EXCEPTION_SINGLE_STEP:
                // First chance: Update the display of the 
                // current instruction and register values.
                //LOG("Executing RET\n");
                dwContinueStatus = RtrSingleStepHandler(TraceEv);
                break;

            case DBG_CONTROL_C:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                LOG("Control-C\n");
                break;

            default:
                // Handle other exceptions. 
                // LOG("Default\n");
                break;
            }

            break;

        case CREATE_THREAD_DEBUG_EVENT:
            // As needed, examine or change the thread's registers 
            // with the GetThreadContext and SetThreadContext functions; 
            // and suspend and resume thread execution with the 
            // SuspendThread and ResumeThread functions. 
            LOG("Create Thread\n");
            dwContinueStatus = RtrOnCreateThreadEvent(TraceEv);
            break;

        case CREATE_PROCESS_DEBUG_EVENT:
            // As needed, examine or change the registers of the
            // process's initial thread with the GetThreadContext and
            // SetThreadContext functions; read from and write to the
            // process's virtual memory with the ReadProcessMemory and
            // WriteProcessMemory functions; and suspend and resume
            // thread execution with the SuspendThread and ResumeThread
            // functions. Be sure to close the handle to the process image
            // file with CloseHandle.

            dwContinueStatus = RtrOnCreateProcessEvent(TraceEv);
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            // Display the thread's exit code. 
            LOG("Exit Thread\n");
            dwContinueStatus = RtrOnExitThreadEvent(TraceEv);
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            // Display the process's exit code. 
            LOG("Exit Process\n");
            dwContinueStatus = RtrOnExitProcessEvent(TraceEv);
            break;

        case LOAD_DLL_DEBUG_EVENT:
            // Read the debugging information included in the newly 
            // loaded DLL. Be sure to close the handle to the loaded DLL 
            // with CloseHandle.

            // dwContinueStatus = RtrOnLoadDllEvent(TraceEv);
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            // Display a message that the DLL has been unloaded. 
            LOG("Unload DLL\n");
            dwContinueStatus = RtrOnUnloadDllEvent(TraceEv);
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            // Display the output debugging string. 
            // LOG("Debug String\n");
            dwContinueStatus = RtrOnOutputDebugStringEvent(TraceEv);
            break;

        case RIP_EVENT:
            LOG("RIP Event\n");
            dwContinueStatus = RtrOnRipEvent(TraceEv);
            break;
        }

        if (dwContinueStatus != DBG_CONTINUE)
        {
            return dwContinueStatus;
        }

        // Resume executing the thread that reported the debugging event. 
        ContinueDebugEvent(TraceEv->dwProcessId,
            TraceEv->dwThreadId,
            dwContinueStatus);
    }
}