#pragma once

// We do this in order to include both 'windows.h' and 'ntstatus.h'
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include    "stdio.h"
#include    <ntstatus.h>

#ifndef     CHAR
typedef char CHAR, *PCHAR;
#endif

#ifndef     BOOLEAN
typedef unsigned __int8 BOOLEAN, *PBOOLEAN;
#endif

#ifndef     QWORD
typedef unsigned __int64 QWORD, *PQWORD;
#endif

typedef struct _EXE_FILE {
    DWORD EntryPointRva;
    DWORD TextSectionRva;
    QWORD ImageBase;
    QWORD EntryPoint;
} EXE_FILE, *PEXE_FILE;

// Array of addresses
#define     STATUS_NON_EXISTENT_ENTRY               ((NTSTATUS)0x10000000)
#define     STATUS_FULL_ARRAY_OF_ADDRESSES          ((NTSTATUS)0x10000001)

// Tag codes
#define     MAX_TAG                                 (QWORD)(0x7FFDull)
#define     SEND_ALLOCATION_STATE_TAG               (QWORD)(0x7FFEull)
#define     ERROR_INSERT_FULL_ARRAY_OF_TAGS         (QWORD)(0x7FFFull)

// Sizes
#define     KB_SIZE                                 1024ULL
#define     MB_SIZE                                 (1024*KB_SIZE)
#define     GB_SIZE                                 (1024*MB_SIZE)
#define     TB_SIZE                                 (1024*GB_SIZE)
#define     PAGE_SIZE                               0x1000

//Tools
#define     BIT_RANGE(i,j)                          (((1ull << ((j) - (i) + 1)) - 1) << (i))
#define     BITS_48_63(addr)                        ((addr) & BIT_RANGE(48, 63))
#define     GET_TAG(addr)                           (BITS_48_63(addr) >> 48)
#define     REMOVE_TAG(addr)                        ((addr) & 0x0000FFFFFFFFFFFF)

// InterlockedCompareExchange
#define     ACQUIRE_MUTEX(mutex)                    while (0 != InterlockedCompareExchange64(&(mutex), 1, 0))

#define LOG_FILE L"C:\\ROProtect.log"
void WriteLog(PCHAR Text);
void WriteLogW(PWCHAR Text);
#define LOG(x) WriteLog(x);
#define LOG_W(x) WriteLogW(x);