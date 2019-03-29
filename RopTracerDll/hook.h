#include "utils.h"

STATUS RtrUnhookModule(SIZE_T ImageBase);
STATUS RtrHookModule(SIZE_T ImageBase);
STATUS RtrFreeHooks(VOID);
STATUS RtrHookRegion(SIZE_T Address, DWORD Length);
STATUS RtrUnhookRegion(SIZE_T Address, DWORD Length);