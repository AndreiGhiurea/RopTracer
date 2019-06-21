#include "callbacks.h"
#include "shlwapi.h"
#include "emu.h"
#include "hook.h"

DWORD
RtrOnLoadDllEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    )
{
    DWORD returnValue = DBG_CONTINUE;
    STATUS status = STATUS_SUCCESS;
    LOAD_DLL_DEBUG_INFO loadInfo = TraceEv->u.LoadDll;

    CHAR filePath[MAX_PATH];
    GetFinalPathNameByHandle(loadInfo.hFile, filePath, MAX_PATH - 1, FILE_NAME_NORMALIZED);
    PathStripPathA(filePath);

    LOG("[TRACER] Loaded DLL: %s - Trying to trace it!\n", filePath);

    status = RtrHookModule((SIZE_T)loadInfo.lpBaseOfDll, loadInfo.hFile);
    if (!SUCCEEDED(status))
    {
        LOG("[ERROR] RtrHookModule failed: 0x%08x\n", status);
        returnValue = STATUS_RTR_INTERNAL_ERROR;
        goto cleanup_and_exit;
    }

    if (!FlushInstructionCache(gExeFile.ProcessHandle, NULL, 0))
    {
        LOG("[ERROR] FlushInstructionCache failed: %d\n", GetLastError());
    }

    LOG("[TRACER] Current patch count: %lld\n", gExeFile.PatchCount);

cleanup_and_exit:
    CloseHandle(loadInfo.hFile);

    return returnValue;
}

DWORD
RtrOnCreateProcessEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    ) 
{
    DWORD returnValue = DBG_CONTINUE;
    STATUS status = STATUS_SUCCESS;
    CREATE_PROCESS_DEBUG_INFO createInfo = TraceEv->u.CreateProcessInfo;

    CHAR filePath[MAX_PATH];
    GetFinalPathNameByHandle(createInfo.hFile, filePath, MAX_PATH - 1, FILE_NAME_NORMALIZED);
    PathStripPathA(filePath);

    LOG("[TRACER] Process Created: %s - Trying to trace it!\n", filePath);

    status = RtrHookModule((SIZE_T)createInfo.lpBaseOfImage, createInfo.hFile);
    if (!SUCCEEDED(status))
    {
        LOG("[ERROR] RtrHookModule failed: 0x%08x\n", status);
        returnValue = STATUS_RTR_INTERNAL_ERROR;
        goto cleanup_and_exit;
    }

    if (!FlushInstructionCache(gExeFile.ProcessHandle, NULL, 0))
    {
        LOG("[ERROR] FlushInstructionCache failed: %d\n", GetLastError());
    }

    LOG("[TRACER] Hooking successful. Current patch count: %lld\n", gExeFile.PatchCount);

cleanup_and_exit:
    CloseHandle(createInfo.hFile);

    return returnValue;
}

DWORD 
RtrOnCreateThreadEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    )
{
    UNREFERENCED_PARAMETER(TraceEv);
    return DBG_CONTINUE;
}

DWORD 
RtrOnExitThreadEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    )
{
    UNREFERENCED_PARAMETER(TraceEv);
    return DBG_CONTINUE;
}

DWORD 
RtrOnExitProcessEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    )
{
    UNREFERENCED_PARAMETER(TraceEv);
    return DBG_CONTINUE;
}

DWORD 
RtrOnUnloadDllEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    )
{
    // For unload we're only given the base address
    // We should keep a list of all the loaded DLLs in the EXE with name and base address and compare it with the one given, maybe even keep a file handle
    // Then we can show what dll is unloaded and with the file handle we can parse the PE so we can unhook all the sections
    // Unhooking isn't really necessary but we can do it to get rid of all the now useless entries in the patch list.

    UNREFERENCED_PARAMETER(TraceEv);
    return DBG_CONTINUE;
}

DWORD 
RtrOnOutputDebugStringEvent(
    _In_ const LPDEBUG_EVENT TraceEv
)
{
    LOG("[DEBUG-STRING] %s\n", TraceEv->u.DebugString.lpDebugStringData);

    UNREFERENCED_PARAMETER(TraceEv);
    return DBG_CONTINUE;
}

DWORD 
RtrOnRipEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    )
{
    UNREFERENCED_PARAMETER(TraceEv);
    return DBG_CONTINUE;
}