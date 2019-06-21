#pragma once
#include "utils.h"

STATUS 
RtrUnhookModule(
    _In_ SIZE_T ImageBase,
    _In_ HANDLE FileHandle
    );

STATUS 
RtrHookModule(
    _In_ SIZE_T ImageBase,
    _In_ HANDLE FileHandle
    );

STATUS 
RtrFreeHooks(
    _In_ VOID
    );

STATUS 
RtrHookRegion(
    _In_ SIZE_T Address, 
    _In_ DWORD Length
    );

STATUS 
RtrUnhookRegion(
    _In_ SIZE_T Address,
    _In_ DWORD Length
    );