#pragma once
#include "utils.h"

STATUS 
RtrEmulateInstruction(
    ZydisDecodedInstruction Instruction, 
    LPCONTEXT ThreadContext
    );