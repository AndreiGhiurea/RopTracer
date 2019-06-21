#pragma once
#include "utils.h"

DWORD
RtrOnLoadDllEvent(
    _In_ const LPDEBUG_EVENT
    );

DWORD 
RtrOnCreateProcessEvent(
    _In_ const LPDEBUG_EVENT
    );

DWORD
RtrOnCreateThreadEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    );

DWORD
RtrOnExitThreadEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    );

DWORD
RtrOnExitProcessEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    );

DWORD
RtrOnUnloadDllEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    );

DWORD
RtrOnOutputDebugStringEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    );

DWORD
RtrOnRipEvent(
    _In_ const LPDEBUG_EVENT TraceEv
    );