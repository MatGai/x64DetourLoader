#include <stdio.h>
//#include "pe.h"
#include <Windows.h>
#include <winternl.h>

#pragma comment( lib, "ntdll" )

/**
* Simple printf wrapper for logging GetLastError, also exits the process!
*
* @param str A string for error details
*/
VOID
LogError(
    LPCSTR str
);

/**
* Searches for a specific processes PID through NtQuerySystemInformation
*
* @param ProcessName A wide-character string for the process name
*
* @return A dword for the processes PID, NULL if not found
*/
DWORD
FindProcessPID(
    LPCWSTR ProcessName
);