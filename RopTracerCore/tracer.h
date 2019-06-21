#pragma once
#include "utils.h"

STATUS
RtrStartTrace(
    _In_ DWORD ProcessId
    );

DWORD
RtrEnterTraceLoop(
    _In_ const LPDEBUG_EVENT DebugEv
    );