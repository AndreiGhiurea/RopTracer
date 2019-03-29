#pragma once
#include "utils.h"

#define TRAP_FLAG_MASK              0x100

LONG WINAPI
RtrBreakpointHandler(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
    );