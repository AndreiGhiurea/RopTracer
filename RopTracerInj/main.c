#include "injector.h"

INT
main(
    INT Argc,
    PCHAR Argv[]
    )
{
    UNREFERENCED_PARAMETER(Argv);
    UNREFERENCED_PARAMETER(Argc);
    /*DWORD pid = 0;
    PCHAR pDllPath = NULL;
    BOOL bErr;

    if (Argc != 3)
    {
        printf("Usage %s <pid> <dll path>\n", Argv[0]);
        return -1;
    }

    pid = strtoul(Argv[1], NULL, 0);
    pDllPath = Argv[2];

    printf("Injecting `%s` into %d...\n", pDllPath, pid);

    bErr = InjectDllIntoProcess(pid, pDllPath);
    printf("Injection %s\n", bErr ? "Succeeded" : "Failed");

    return !bErr;*/

    HMODULE hMod = LoadLibrary("C:\\Users\\aghiurea\\Desktop\\School\\Licenta\\RopTracer\\bin\\x64\\Debug\\RopTracerDll.dll");
    if (!hMod)
    {
        DWORD dw = GetLastError();
        printf("The library could not load.  Error %d", dw);
    }
    else
    {
        printf("Library loaded successfully");
        FreeLibrary(hMod);
    }

    return 0;
}