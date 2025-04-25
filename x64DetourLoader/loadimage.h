#pragma once
#include "util.h"


/**
* Gets the dll from disk and puts it into buffer, set buffersize to NULL if you want to get the size of dll.
* 
* @param Path A string for the path to the dll on disk
* @param Buffer A byte pointer to store the dll
* @param BufferSize A ulong64 size for the size of the buffer for the dll
* 
* @return FALSE if failed, TRUE if succeeded.
*/
BOOLEAN
GetFileFromDisk(
    _In_ LPCSTR        Path,
    _Out_opt_ PBYTE    Buffer,
    _Inout_ PDWORD BufferSize
);

/**
*  Takes in a raw DLL from disk and properly formats headers and sections to their proper RVA.
* 
* @param FileImage A byte buffer pointer holding the DLL.
* @param MemoryImage A byte buffer for a properly formated PE image.
* 
* @return FALSE if failed,TRUE if succeeded.
*/
BOOLEAN 
AlignFileImage(
    _In_ PBYTE FileImage,
    _Out_ PBYTE* MemoryImage
);


/**
* Allocates a buffer into to target process, then writes the properly formatted PE image into the process.
* 
* @param ProcessHandle A handle to the target process.
* @param MemoryImage   A byte buffer that contains the valid PE image.
* 
* @return The base address of the image in memory, NULL if something went wrong.
*/
ULONG64
WriteImageToProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PBYTE MemoryImage
);
