#pragma once
#include "utils.h"

DWORD
RtrBreakpointHandler(
    _In_ const LPDEBUG_EVENT
    );

DWORD
RtrSingleStepHandler(
    _In_ const LPDEBUG_EVENT
    );

DWORD RtrValidateRetHandler(
    _In_ const PCONTEXT ThreadContext,
    _In_ const LPDEBUG_EVENT TraceEv
    );