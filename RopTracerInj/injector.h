#pragma once
#include "utils.h"

#define KERNEL32_NAME       "Kernel32.dll"
#define LOADLIBRARYA_NAME   "LoadLibraryA"
#define KERNEL32_PATH       "C:\\Windows\\System32\\Kernel32.dll"

BOOLEAN
InjectDllIntoProcess(
    _In_ const DWORD    Pid,
    _In_ const PCHAR    DllPath
);
