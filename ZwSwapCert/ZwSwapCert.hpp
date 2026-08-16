#pragma once
#include <ntifs.h>
#include <windef.h>
#include <intrin.h>

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D
#endif
#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE 0x00004550
#endif

typedef struct _IMAGE_DOS_HEADER
{
	unsigned short e_magic;
	unsigned short e_cblp;
	unsigned short e_cp;
	unsigned short e_crlc;
	unsigned short e_cparhdr;
	unsigned short e_minalloc;
	unsigned short e_maxalloc;
	unsigned short e_ss;
	unsigned short e_sp;
	unsigned short e_csum;
	unsigned short e_ip;
	unsigned short e_cs;
	unsigned short e_lfarlc;
	unsigned short e_ovno;
	unsigned short e_res[4];
	unsigned short e_oemid;
	unsigned short e_oeminfo;
	unsigned short e_res2[10];
	long e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
	unsigned short Machine;
	unsigned short NumberOfSections;
	unsigned long TimeDateStamp;
	unsigned long PointerToSymbolTable;
	unsigned long NumberOfSymbols;
	unsigned short SizeOfOptionalHeader;
	unsigned short Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
	unsigned long VirtualAddress;
	unsigned long Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
	unsigned short Magic;
	unsigned char MajorLinkerVersion;
	unsigned char MinorLinkerVersion;
	unsigned long SizeOfCode;
	unsigned long SizeOfInitializedData;
	unsigned long SizeOfUninitializedData;
	unsigned long AddressOfEntryPoint;
	unsigned long BaseOfCode;
	unsigned __int64 ImageBase;
	unsigned long SectionAlignment;
	unsigned long FileAlignment;
	unsigned short MajorOperatingSystemVersion;
	unsigned short MinorOperatingSystemVersion;
	unsigned short MajorImageVersion;
	unsigned short MinorImageVersion;
	unsigned short MajorSubsystemVersion;
	unsigned short MinorSubsystemVersion;
	unsigned long Win32VersionValue;
	unsigned long SizeOfImage;
	unsigned long SizeOfHeaders;
	unsigned long CheckSum;
	unsigned short Subsystem;
	unsigned short DllCharacteristics;
	unsigned __int64 SizeOfStackReserve;
	unsigned __int64 SizeOfStackCommit;
	unsigned __int64 SizeOfHeapReserve;
	unsigned __int64 SizeOfHeapCommit;
	unsigned long LoaderFlags;
	unsigned long NumberOfRvaAndSizes;
	struct _IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64
{
	unsigned long Signature;
	struct _IMAGE_FILE_HEADER FileHeader;
	struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER
{
	unsigned char Name[8];
	union
	{
		union
		{
			unsigned long PhysicalAddress;
			unsigned long VirtualSize;
		};
	} Misc;
	unsigned long VirtualAddress;
	unsigned long SizeOfRawData;
	unsigned long PointerToRawData;
	unsigned long PointerToRelocations;
	unsigned long PointerToLinenumbers;
	unsigned short NumberOfRelocations;
	unsigned short NumberOfLinenumbers;
	unsigned long Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

extern "C" UNICODE_STRING DriverPath;
extern "C" FILE_STANDARD_INFORMATION fileInfo;
extern "C" PVOID FileCopy;
extern "C" HANDLE fileHandle;
extern "C" PIMAGE_DOS_HEADER originalHeaders;
extern "C" SIZE_T textSize;
extern "C" PVOID driverStartSaved;
extern "C" PVOID originalTextSection;
extern "C" PVOID TextSectionAddress;
extern "C" DWORD SizeOfRawData;
extern "C" PVOID PeBuckup;
extern "C" SIZE_T DriverSize;

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

namespace Utils
{
	NTSTATUS SwapDriver(PUNICODE_STRING DriverPath, PVOID DriverBuffer, SIZE_T BufferSize);

	PVOID MapDriver(UINT64 ModuleBase, UINT64 DriverBuffer);
}

extern "C"
{
	NTSTATUS ScDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

	DWORD write_to_read_only_memory(void* address, void* buffer, size_t size);

	int GetPeHdrSize();

	void PrepareDriverForUnload();
}
