#include "injector.h"
#pragma check_stack(off)

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