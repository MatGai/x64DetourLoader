#include "loadimage.h"

BOOLEAN
GetFileFromDisk(
    _In_ LPCSTR        Path,
    _Out_opt_ PBYTE    Buffer,
    _Inout_ PDWORD BufferSize
)
{
    //
    // Open a handle to file with read access
    //
    HANDLE FileHandle = CreateFileA(
        Path,
        GENERIC_READ,             // open for reading
        FILE_SHARE_READ,          // share for reading
        NULL,                     // default security
        OPEN_EXISTING,            // existing file only
        FILE_ATTRIBUTE_NORMAL,    // normal file
        NULL                      // no attr. template
        );                                   
        
    if (FileHandle == INVALID_HANDLE_VALUE)
    {
        LogError("Failed to get the file handle in GetDllFromDisk");
    }

    //
    // if we want to just get the size of the file
    //
    if ( BufferSize )
    {
        if (*BufferSize == NULL)
        {
            *BufferSize = (ULONG64)GetFileSize(FileHandle, NULL);
            CloseHandle(FileHandle);
            return FALSE;
        }
    }

    if (!Buffer)
    {
        CloseHandle(FileHandle);
        return FALSE;
    }

    //
    // Read the dll from disk into our buffer, we can check if buffer size and read size are the same for sanity checking
    // 
    DWORD ReadSize;
    if ( !ReadFile(FileHandle, Buffer, *BufferSize, &ReadSize, NULL) )
    {
        CloseHandle(FileHandle);
        LogError("Failed to read file in GetDllFromDisk");
        return FALSE;
    }

    if (ReadSize <= 0 && ReadSize != *BufferSize)
    {
        CloseHandle(FileHandle);
        LogError("Something went wrong with the read and buffer sizes!");
        return FALSE;
    }

    CloseHandle(FileHandle);
    return TRUE;
}

BOOLEAN
AlignFileImage(
    _In_ PBYTE FileImage, 
    _Out_ PBYTE* MemoryImage
)
{
    if ( !FileImage || !MemoryImage )
    {
        printf("Invalid input pointers.\n");
        return FALSE;
    }

    //
    // get the dos head from file image amd check against e_magic
    //
    PIMAGE_DOS_HEADER FileDosHeader = (PIMAGE_DOS_HEADER)FileImage;
    if (FileDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        LogError("Invalid DOS header signature.\n");
        return FALSE;
    }

    //
    // get the Nt headers using the e_lfanew offset.
    //
    PIMAGE_NT_HEADERS FileNtHeaders = (PIMAGE_NT_HEADERS)(FileImage + FileDosHeader->e_lfanew);
    if (FileNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        LogError("Invalid NT header signature.\n");
        return FALSE;
    }

    //
    // get the total size of the image
    //
    SIZE_T imageSize = FileNtHeaders->OptionalHeader.SizeOfImage;

    //
    // malloc a new buffer for the memory image.
    //
    *MemoryImage = (PBYTE)malloc(imageSize);
    if (*MemoryImage == NULL)
    {
        LogError("Memory allocation failed.\n");
        return FALSE;
    }

    //
    // copy the nt headers into the new buffer
    //
    SIZE_T headersSize = FileNtHeaders->OptionalHeader.SizeOfHeaders;
    memcpy(*MemoryImage, FileImage, headersSize);

    //
    // use the IMAGE_FIRST_SECTION macro to get the pointer to the first section
    //
    PIMAGE_SECTION_HEADER FileSectionHeader = IMAGE_FIRST_SECTION(FileNtHeaders);

    //
    // loop through each section and copy its raw data to the appropriate offset
    // in the new memory buffer based on the sections virtual address
    //
    for ( SIZE_T i = 0; i < FileNtHeaders->FileHeader.NumberOfSections; i++ )
    {
        //
        // pointer to the current section header
        //
        PIMAGE_SECTION_HEADER CurrentSection = &FileSectionHeader[i];

        //
        // make sure to only copy sections with raw data
        //
        if (CurrentSection->SizeOfRawData > 0)
        {
            memcpy(
                *MemoryImage + CurrentSection->VirtualAddress,
                FileImage + CurrentSection->PointerToRawData,
                CurrentSection->SizeOfRawData
            );
        }
    }

    return TRUE;
}

ULONG64 
WriteImageToProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PBYTE MemoryImage
)
{
    PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)MemoryImage;

    if( !ImageDosHeader || ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
    {
        LogError("Trying to write invalid image to process");
        return NULL;
    }

    PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(MemoryImage + ImageDosHeader->e_lfanew);

    //
    // allocate a block of memory in the process
    //
    ULONG64 ImageBase = (ULONG64)VirtualAllocEx( 
        ProcessHandle, 
        NULL, 
        ImageNtHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    if (!ImageBase)
    {
        LogError( "VirtualAllocEx failed allocating block of memory in process" );
        return NULL;
    }

    //
    // write the image file into the block of memory allocated
    //
    SIZE_T BytesWritten = 0;
    WriteProcessMemory(ProcessHandle, (PVOID)ImageBase, MemoryImage, ImageNtHeaders->OptionalHeader.SizeOfImage, &BytesWritten);

    if (BytesWritten == ImageNtHeaders->OptionalHeader.SizeOfImage)
    {
        return ImageBase;
    }

    //
    // assuming write process memory failed!
    //
    return NULL;
}

