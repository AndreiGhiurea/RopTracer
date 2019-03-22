#include "utils.h"

STATUS RtrUnhookModule(QWORD ImageBase);
STATUS RtrHookModule(QWORD ImageBase);
STATUS RtrFreeHooks(VOID);
STATUS RtrHookRegion(QWORD Address, DWORD Length);
STATUS RtrUnhookRegion(QWORD Address, DWORD Length);