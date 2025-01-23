#pragma once
#include "nt.h" 
//#include <winternl.h>


PPEB
PeCurrentPeb(

);

PLDR_DATA_TABLE_ENTRY
PeRetrieveImageBase(
	LPCWSTR ImageName
);

PIMAGE_DOS_HEADER
PeImageDosHeader(
	PVOID ImageBase
);

PIMAGE_NT_HEADERS64
PeImageNtHeader(
	PVOID ImageBase
);

PIMAGE_OPTIONAL_HEADER
PeImageOptionalHeader(
	PVOID ImageBase
);

INT64
PeDumpExportNames(
	PVOID   ImageBase
);

PIMAGE_FILE_HEADER
PeImageFileHeader(
	PVOID ImageBase
);

INT64
PeRetrieveImageImport(
	PVOID   ImageBase,
	LPCSTR  ImportName
);

INT64
PeRetrieveImageExport(
	PVOID   ImageBase,
	LPCSTR  ExportName
);