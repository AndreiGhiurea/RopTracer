#include "utils.h"

void WriteLog(PCHAR Text)
{
    HANDLE hfile = CreateFileW(LOG_FILE, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written;
    WriteFile(hfile, Text, (DWORD)strlen(Text), &written, NULL);
    WriteFile(hfile, "\r\n", 2, &written, NULL);
    CloseHandle(hfile);
}

void WriteLogW(PWCHAR Text)
{
    HANDLE hfile = CreateFileW(LOG_FILE, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written;
    WriteFile(hfile, Text, (DWORD)wcslen(Text) * 2, &written, NULL);
    WriteFile(hfile, L"\r\n", 4, &written, NULL);
    CloseHandle(hfile);
}