#include "loadimage.h"


int main(

)
{
    //
    // TODO: implement a system of getting a target prcoess and a dll to map into. 
    // TODO: create a manual mapper to load a selected dll into a target process.
    //
    CONST CHAR* DllBuffer  = "C:/Users/Opli/source/repos/x64DetourDllTest/x64/Debug/x64DetourDll.dll";
    CONST CHAR* ExeBuffer  = "C:/Users/Opli/source/repos/x64DetourTarget/x64/Release/x64DetourTarget.exe";

    DWORD ProcessPID     = FindProcessPID(L"x64DetourTarget.exe");
    HANDLE ProcessHandle = nullptr;

    DWORD DllSize = NULL;
    GetFileFromDisk(DllBuffer, NULL, &DllSize);

    PBYTE DllByteBuffer = (PBYTE)malloc(DllSize);

    GetFileFromDisk(DllBuffer, DllByteBuffer, &DllSize);
    
    if ( !ProcessPID ) // just assume that the process is not running
    {
        //
        // start the process up so we can get a handle to it
        //

        STARTUPINFOA StartupInfo               = { };
        PROCESS_INFORMATION ProcessInformation = { };

        StartupInfo.cb = sizeof( StartupInfo );

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

        if ( !result )
        {
            LogError("Failed to create process");
        }

        if ( !ProcessInformation.hProcess || !ProcessInformation.hThread )
        {
            LogError("Failed to get process handle from CreateProcessA");
        }

        CloseHandle(ProcessInformation.hThread);
        ProcessHandle = ProcessInformation.hProcess;
    }
    else
    {
        //
        // process should be running so try to get a handle to it through the PID
        //
        ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessPID );
        if (!ProcessHandle)
        {
            LogError("Failed to get process handle from NtQuerySystemInformation");
        }
    }

    //
    // allocate a buffer of memory in the target process
    //
    PVOID AllocBuffer = (PVOID)VirtualAllocEx(
        ProcessHandle,
        NULL,
        MAX_PATH,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!AllocBuffer)
    {
        LogError("Failed to allocate memory in process");
    }

    //
    // write our dll into the allocated buffer
    //
    BOOL HasWritten = WriteProcessMemory(
        ProcessHandle,
        AllocBuffer,
        DllBuffer,
        MAX_PATH,
        NULL
    );

    if (!HasWritten)
    {
        LogError("Failed to write memory in process");
    }

    FARPROC LoadLibraryFn = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"); // change this to either include lib, or get the function through gs register

    if (!LoadLibraryFn)
    {
        LogError("Failed to get LoadLibraryA address");
    }

    //
    // execute our allcated dll with create remote thread
    //
    HANDLE RemoteThread = CreateRemoteThread(
        ProcessHandle,
        NULL,
        NULL,
        (LPTHREAD_START_ROUTINE)LoadLibraryFn,
        AllocBuffer,
        NULL,
        NULL
    );

    if (!RemoteThread)
    {
        CloseHandle(RemoteThread);
        LogError("Failed to create remote thread");
    }

    //
    // should wait for the create thread to finish but we are winging it
    //
    CloseHandle(RemoteThread);
    CloseHandle(ProcessHandle);
  
    return 0;
}