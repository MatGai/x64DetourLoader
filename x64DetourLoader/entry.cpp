#include <stdio.h>
#include "pe.h"


VOID LogError(
    LPCSTR str
)
{
    printf("Error: %s - [ %lu ]\n", str, GetLastError());
    system("pause");
    ExitProcess(1);
}

typedef NTSTATUS ( NTAPI* NtQuerySystemInformationDef ) (
                                                        _In_      SYSTEM_INFORMATION_CLASS   SystemInformationClass,
                                                        _Inout_   PVOID                      SystemInformation,
                                                        _In_      DWORD                      SystemInformationLength,
                                                        _Out_opt_ PDWORD                     ReturnLength
                                                       );

static NtQuerySystemInformationDef g_NtQuerySystemInformation = NULL;

DWORD FindProcessPID(
   CONST WCHAR* ProcessName
)
{
    PLDR_DATA_TABLE_ENTRY NtDllImage = PeRetrieveImageBase(L"NTDLL.dll");

    if ( !NtDllImage )
    {
        LogError("Failed to get NTDLL image");
    }

    g_NtQuerySystemInformation = (NtQuerySystemInformationDef)PeRetrieveImageExport(
        NtDllImage->DllBase,
        "NtQuerySystemInformation"
    );

    if ( !g_NtQuerySystemInformation )
    {
        LogError("Failed to get NtQuerySystemInformation address");
    }


    DWORD dwSize;
    g_NtQuerySystemInformation(SystemExtendedProcessInformation, NULL, 0, &dwSize); // when size is null, it will return the required size

    // allocate bit more memory just incase!
    dwSize += 0x1000;

    PVOID pBuffer = malloc( dwSize );
    if ( !pBuffer )
    {
        LogError("Failed to allocate memory for process information");
    }

    NTSTATUS status = g_NtQuerySystemInformation(SystemExtendedProcessInformation, pBuffer, dwSize, &dwSize); // should return buffer of SYSTEM_PROCESS_INFORMATION in pBuffer

    if ( status < 0 )
    {
        free(pBuffer);
        LogError("NtQuerySystemInformation has failed");
    }

    PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)pBuffer;

    DWORD PID = 0;

    do
    {
        pCurrent = (PSYSTEM_PROCESS_INFORMATION)(((PBYTE)pCurrent) + pCurrent->NextEntryOffset); // this is how you iterate through the list

        if ( !pCurrent->ImageName.Buffer && !pCurrent->ImageName.Length )
        {
            continue;
        }

        if ( _wcsicmp( pCurrent->ImageName.Buffer, ProcessName ) == 0 )
        {
            PID = (DWORD)(ULONG_PTR)pCurrent->UniqueProcessId;
            break;
        }

    } while ( pCurrent->NextEntryOffset );

    free(pBuffer);
    return PID;
}

int main(

)
{
    CONST CHAR* DllBuffer  = "C:/Users/Opli/source/repos/x64DetourDll/x64/Debug/x64DetourDll.dll";
    CONST CHAR* ExeBuffer  = "C:/Users/Opli/source/repos/x64DetourTarget/x64/Release/x64DetourTarget.exe";

    DWORD ProcessPID     = FindProcessPID(L"x64DetourTarget.exe");
    HANDLE ProcessHandle = nullptr;
    
    if ( !ProcessPID )
    {
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
        ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessPID );
        if (!ProcessHandle)
        {
            LogError("Failed to get process handle from NtQuerySystemInformation");
        }
    }

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

    FARPROC LoadLibraryFn = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"); // change this to use the PE shit sometime soon?

    if (!LoadLibraryFn)
    {
        LogError("Failed to get LoadLibraryA address");
    }

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

    CloseHandle(RemoteThread);
    CloseHandle(ProcessHandle);
  
    return 0;
}