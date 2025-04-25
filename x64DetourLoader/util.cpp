#pragma once
#include "util.h"

VOID
LogError(
    LPCSTR str
)
{
    printf("Error: %s - [ %lu ]\n", str, GetLastError());
    system("pause");
    ExitProcess(1);
}

DWORD
FindProcessPID(
    LPCWSTR ProcessName
)
{
    //
    // when 'SystemInformationLength' is null, it will return the required size
    //
    ULONG dwSize = NULL;
    NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)57 /*SystemExtendedProcessInformation*/, NULL, 0, &dwSize);

    //
    // allocate bit more memory just incase!
    //
    dwSize += 0x128;

    PVOID pBuffer = malloc(dwSize);
    if (!pBuffer)
    {
        LogError("Failed to allocate memory for process information");
        return NULL;
    }

    //
    // should return buffer of SYSTEM_PROCESS_INFORMATION in pBuffer
    //
    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)57 /*SystemExtendedProcessInformation*/, pBuffer, dwSize, &dwSize);

    if (status < 0)
    {
        free(pBuffer);
        LogError("NtQuerySystemInformation has failed");
        return NULL;
    }

    PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)pBuffer;

    if (!pCurrent || !pCurrent->NextEntryOffset)
    {
        return NULL;
    }

    DWORD PID = NULL;

    do
    {
        //
        // basically a linked list, adds offset from current pointer
        //
        pCurrent = (PSYSTEM_PROCESS_INFORMATION)(((PBYTE)pCurrent) + pCurrent->NextEntryOffset);

        if (!pCurrent->ImageName.Buffer && !pCurrent->ImageName.Length)
        {
            continue;
        }

        if (_wcsicmp(pCurrent->ImageName.Buffer, ProcessName) == 0)
        {
            // found PID, set it and get out of here
            PID = (DWORD)(ULONG_PTR)pCurrent->UniqueProcessId;
            break;
        }

    } while (pCurrent->NextEntryOffset);

    free(pBuffer);
    return PID;
}