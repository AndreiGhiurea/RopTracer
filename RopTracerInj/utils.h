#pragma once

// We do this in order to include both 'windows.h' and 'ntstatus.h'
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <psapi.h>
#include <ntstatus.h>
#include <stdio.h>

#ifndef     CHAR
typedef char CHAR, *PCHAR;
#endif

#ifndef     BOOLEAN
typedef unsigned __int8 BOOLEAN, *PBOOLEAN;
#endif

#ifndef     QWORD
typedef unsigned __int64 QWORD, *PQWORD;
#endif

// Sizes
#define     KB_SIZE                     1024ULL
#define     MB_SIZE                     (1024*KB_SIZE)
#define     GB_SIZE                     (1024*MB_SIZE)
#define     TB_SIZE                     (1024*GB_SIZE)
#define     PAGE_SIZE                   0x1000

#define     MAX_NUMBER_OF_PACKAGES      KB_SIZE
#define     MAX_NUMBER_OF_TARGETS       KB_SIZE
#define     MAX_LENGTH                  KB_SIZE