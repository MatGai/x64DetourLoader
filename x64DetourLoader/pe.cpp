#include "pe.h"
#include <iostream>

PPEB
PeCurrentPeb(

)
{
	return (PPEB)__readgsqword(
		0x60
	);
}

PLDR_DATA_TABLE_ENTRY
PeRetrieveImageBase(
	LPCWSTR ImageName
)
{
	PPEB Peb = PeCurrentPeb();

	if (!Peb)
	{
		return nullptr;
	}

	PPEB_LDR_DATA Ldr = (PPEB_LDR_DATA)Peb->Ldr;

	if (!Ldr)
	{
		return nullptr;
	}

	for (PLIST_ENTRY CurrentLink = Ldr->InLoadOrderModuleList.Flink; CurrentLink && CurrentLink != &Ldr->InLoadOrderModuleList; CurrentLink = CurrentLink->Flink)
	{
		PLDR_DATA_TABLE_ENTRY TableEntry = nullptr;

		TableEntry = CONTAINING_RECORD(
			CurrentLink,
			LDR_DATA_TABLE_ENTRY,
			InLoadOrderLinks
		);

		if (!TableEntry)
		{
			continue;
		}

		if (_wcsicmp(ImageName, TableEntry->BaseDllName.Buffer) == 0)
		{
			return TableEntry;
		}
	}

	return nullptr;
}

PIMAGE_DOS_HEADER
PeImageDosHeader(
	PVOID ImageBase
)
{
	if (PIMAGE_DOS_HEADER(ImageBase)->e_magic == IMAGE_DOS_SIGNATURE)
	{
		return PIMAGE_DOS_HEADER(ImageBase);
	}

	return nullptr;
}

PIMAGE_NT_HEADERS64
PeImageNtHeader(
	PVOID ImageBase
)
{
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((INT64)ImageBase + (PeImageDosHeader(ImageBase)->e_lfanew));

	if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
	{
		return NtHeader;
	}

	return nullptr;
}

PIMAGE_OPTIONAL_HEADER
PeImageOptionalHeader(
	PVOID ImageBase
)
{
	return PIMAGE_OPTIONAL_HEADER(&PeImageNtHeader(ImageBase)->OptionalHeader);
}

PIMAGE_FILE_HEADER
PeImageFileHeader(
	PVOID ImageBase
)
{
	return PIMAGE_FILE_HEADER(&PeImageNtHeader(ImageBase)->FileHeader);
}

INT64
PeRetrieveImageImport(
	PVOID   ImageBase,
	LPCSTR  ImportName
)
{
	IMAGE_DATA_DIRECTORY
		ImageDataDirectory =
		PeImageOptionalHeader(
			ImageBase
		)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!ImageDataDirectory.Size || ImageDataDirectory.VirtualAddress)
	{
		return 0x0;
	}

	PIMAGE_IMPORT_DESCRIPTOR
		ImageImportDescriptorTable =
		(PIMAGE_IMPORT_DESCRIPTOR)(ImageDataDirectory.VirtualAddress + (INT64)ImageBase);

	if (!ImageImportDescriptorTable)
	{
		return 0x0;
	}

	for (; ImageImportDescriptorTable->Name; ++ImageImportDescriptorTable)
	{
		PIMAGE_THUNK_DATA LookupTable = (PIMAGE_THUNK_DATA)(ImageImportDescriptorTable->OriginalFirstThunk + (INT64)ImageBase);
		PIMAGE_THUNK_DATA AddressTable = (PIMAGE_THUNK_DATA)(ImageImportDescriptorTable->FirstThunk + (INT64)ImageBase);

		if (!LookupTable || !AddressTable)
		{
			continue;
		}

		for (; LookupTable && AddressTable;)
		{
			if (!LookupTable->u1.AddressOfData || !AddressTable->u1.AddressOfData)
			{
				continue;
			}

			INT64 CurrentRoutine = (INT64)(AddressTable->u1.AddressOfData + (INT64)ImageBase);
			LPCSTR CurrentName = (LPCSTR)(LookupTable->u1.AddressOfData + (INT64)ImageBase);

			if (!CurrentRoutine || !CurrentName)
			{
				continue;
			}

			if (_stricmp(CurrentName, ImportName) == 0)
			{
				return CurrentRoutine;
			}
		}
	}

	return 0x0;
}

INT64
PeRetrieveImageExport(
	PVOID   ImageBase,
	LPCSTR  ExportName
)
{
	IMAGE_DATA_DIRECTORY
		ImageDataDirectory =
		PeImageOptionalHeader(
			ImageBase
		)->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (!ImageDataDirectory.Size || !ImageDataDirectory.VirtualAddress)
	{
		return 0x0;
	}

	PIMAGE_EXPORT_DIRECTORY
		ImageExportDataDirectory =
		(PIMAGE_EXPORT_DIRECTORY)(ImageDataDirectory.VirtualAddress + (INT64)ImageBase);

	if (!ImageExportDataDirectory || !ImageExportDataDirectory->TimeDateStamp)
	{
		return 0x0;
	}

	PINT16 OrdinalTable = (PINT16)(ImageExportDataDirectory->AddressOfNameOrdinals + (INT64)ImageBase);
	PINT32 RoutineTable = (PINT32)(ImageExportDataDirectory->AddressOfFunctions + (INT64)ImageBase);
	PINT32 NameTable = (PINT32)(ImageExportDataDirectory->AddressOfNames + (INT64)ImageBase);

	if (!OrdinalTable || !RoutineTable || !NameTable)
	{
		return 0x0;
	}

	for (UINT Index = 0; Index < ImageExportDataDirectory->NumberOfNames; ++Index)
	{
		INT16 CurrentOrdinal = (INT16)(OrdinalTable[Index]);
		INT64 CurrentRoutine = (INT64)(RoutineTable[CurrentOrdinal] + (INT64)ImageBase);
		LPCSTR CurrentName = (LPCSTR)(NameTable[Index] + (INT64)ImageBase);

		if (!CurrentRoutine || !CurrentName)
		{
			continue;
		}

		if (_stricmp(CurrentName, ExportName) == 0)
		{
			return CurrentRoutine;
		}
	}

	return 0x0;
}