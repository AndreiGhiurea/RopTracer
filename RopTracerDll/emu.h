#pragma once
#include "utils.h"

STATUS EmulateInstruction(ZydisDecodedInstruction Instruction, PEXCEPTION_POINTERS ExceptionInfo);