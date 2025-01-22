#include <Windows.h>
#include <stdio.h>

VOID LogError(
    LPCSTR str
)
{
    printf("Error: %s - [ %lu ]\n", str, GetLastError());
    system("pause");
    ExitProcess(1);
}

int main(

)
{
    CONST CHAR* DllBuffer = "C:/Users/Opli/source/repos/x64DetourDll/x64/Debug/x64DetourDll.dll";
    CONST CHAR* ExeBuffer  = "C:/Users/Opli/source/repos/x64Detour/x64/Release/x64Detour.exe";

    printf("Got full dll path: %s\n", DllBuffer);
    printf("Got full exe path: %s\n", ExeBuffer);

    STARTUPINFOA StartupInfo               = { };
    PROCESS_INFORMATION ProcessInformation = { };

    StartupInfo.cb = sizeof(StartupInfo);

    BOOL result = CreateProcessA(
        ExeBuffer,
        NULL, 
        NULL, 
        NULL, 
        FALSE, 
        CREATE_NEW_CONSOLE,
        NULL, 
        NULL, 
        &StartupInfo, 
        &ProcessInformation
    );

    if (!result)
    {
        LogError("Failed to create process");
    }

    if (!ProcessInformation.hProcess)
    {
        printf("Failed to get process handle\n");
        system("pause");
        return 1;
    }

    PVOID AllocBuffer = (PVOID)VirtualAllocEx(
        ProcessInformation.hProcess,
        NULL,
        MAX_PATH,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!AllocBuffer)
    {
        LogError("Failed to allocate memory in process");
    }

    BOOL HasWritten = WriteProcessMemory(
        ProcessInformation.hProcess,
        AllocBuffer,
        DllBuffer,
        MAX_PATH,
        NULL
    );

    if (!HasWritten)
    {
        LogError("Failed to write memory in process");
    }

    FARPROC LoadLibraryFn = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");

    if (!LoadLibraryFn)
    {
        LogError("Failed to get LoadLibraryA address");
    }

    HANDLE RemoteThread = CreateRemoteThread(
        ProcessInformation.hProcess,
        NULL,
        NULL,
        (LPTHREAD_START_ROUTINE)LoadLibraryFn,
        AllocBuffer,
        NULL,
        NULL
    );

    if (!RemoteThread)
    {
        LogError("Failed to create remote thread");
    }

    CloseHandle(RemoteThread);
    CloseHandle(ProcessInformation.hProcess);
    CloseHandle(ProcessInformation.hThread);

    system("pause");

    return 0;
}