#pragma once

// x86 disassembler
#include <Zydis/Zydis.h>
// We do this in order to include both 'windows.h' and 'ntstatus.h'
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include    "stdio.h"
#include    <ntstatus.h>
#include "tlhelp32.h"

#ifndef     CHAR
typedef char CHAR, *PCHAR;
#endif

#ifndef     BOOLEAN
typedef unsigned __int8 BOOLEAN, *PBOOLEAN;
#endif

#ifndef     QWORD
typedef unsigned __int64 QWORD, *PQWORD;
#endif

typedef struct _RET_PATCH {
    LIST_ENTRY Link;
    BOOLEAN Disabled;
    SIZE_T Address;
    BYTE InstructionBytes[16];
    ZydisDecodedInstruction Instruction;
} RET_PATCH, *PRET_PATCH;

typedef struct _EXE_FILE {
    DWORD EntryPointRva;
    DWORD TextSectionRva;
    SIZE_T ImageBase;
    SIZE_T EntryPoint;
    SIZE_T LastAddr;
    LIST_ENTRY InstructionPatchList;
    QWORD PatchCount;
} EXE_FILE, *PEXE_FILE;

extern EXE_FILE gExeFile;

#define STATUS           NTSTATUS
#define SUCCESS(x)       ((x)>=0)

#ifdef _DEBUG
    #define LOG(s, ...)             printf(s, __VA_ARGS__)
#else
    #define LOG(s, ...)
#endif // DEBUG


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

STATUS
RtrSuspendThreads(VOID);

STATUS
RtrResumeThreads(VOID);

FORCEINLINE
VOID
InitializeListHead(
    _Out_ PLIST_ENTRY ListHead
    )
{
    ListHead->Flink = ListHead->Blink = ListHead;
    return;
}

_Must_inspect_result_
BOOLEAN
CFORCEINLINE
IsListEmpty(
    _In_ const LIST_ENTRY * ListHead
    )
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
BOOLEAN
RemoveEntryList(
    _In_ PLIST_ENTRY Entry
    )
{

    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}

FORCEINLINE
PLIST_ENTRY
RemoveHeadList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

FORCEINLINE
PLIST_ENTRY
RemoveTailList(
    _Inout_ PLIST_ENTRY ListHead
    )
{

    PLIST_ENTRY Blink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Blink;
    Blink = Entry->Blink;
    ListHead->Blink = Blink;
    Blink->Flink = ListHead;
    return Entry;
}

FORCEINLINE
VOID
InsertTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ __drv_aliasesMem PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Blink;

    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
    return;
}


FORCEINLINE
VOID
InsertHeadList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ __drv_aliasesMem PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
    return;
}