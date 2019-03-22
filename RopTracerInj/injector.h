#pragma once
#include "utils.h"

#define KERNEL32_NAME       "kernel32.dll"
#define LOADLIBRARYA_NAME   "LoadLibraryA"
#define FREELIBRARY_NAME	"FreeLibrary"
#define KERNEL32_PATH       "C:\\Windows\\System32\\Kernel32.dll"

BOOLEAN
InjectDllIntoProcess(
    _In_ const HANDLE Process,
    _In_ const PCHAR DllPath
);