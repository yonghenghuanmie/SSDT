#pragma once

#include <ntddk.h>

#ifndef __cplusplus
typedef unsigned char bool;
#define true	1
#define false	0
#endif // !__cplusplus

typedef unsigned char	BYTE;
typedef unsigned short	WORD;
typedef unsigned int	BOOL;
typedef unsigned int	UINT;
typedef unsigned long	DWORD;


#define EINVAL          22
#define ERANGE          34

#undef KdPrintEx
#ifdef DBG
#define KdPrintEx(ComponentId,Level,Format,...) DbgPrintEx(ComponentId,Level,Format,__VA_ARGS__)
#else
#define KdPrintEx(ComponentId,Level,Format,...)
#endif // DBG


typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE,*PSYSTEM_SERVICE_TABLE;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	ULONG Unknow1;
	ULONG Unknow2;
	ULONG Unknow3;
	ULONG Unknow4;
	PVOID64 Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY,*PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;//内核中以加载的模块的个数
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION,*PSYSTEM_MODULE_INFORMATION;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER,*PIMAGE_FILE_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;     // RVA from base of image
	DWORD   AddressOfNames;         // RVA from base of image
	DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY,*PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64,*PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64,*PIMAGE_NT_HEADERS64;

typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
} IMAGE_SECTION_HEADER,*PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER          40

NTKERNELAPI NTSTATUS ZwQuerySystemInformation (
	_In_      ULONG		SystemInformationClass,
	_Inout_   PVOID		SystemInformation,
	_In_      ULONG		SystemInformationLength,
	_Out_opt_ PULONG	ReturnLength
);
#define SystemModuleInformation 11
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

NTKERNELAPI UCHAR *PsGetProcessImageFileName(PEPROCESS Process);

NTKERNELAPI NTSTATUS KeUserModeCallback (
	IN	ULONG	ApiNumber,
	IN	PVOID	InputBuffer,
	IN	ULONG	InputLength,
	OUT PVOID	*OutputBuffer,
	IN	PULONG	OutputLength
);
NTKERNELAPI NTSTATUS ZwQueryInformationProcess (
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

NTKERNELAPI NTSTATUS ZwAllocateVirtualMemory(
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID     *BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
);

NTKERNELAPI NTSTATUS ZwFreeVirtualMemory(
	_In_    HANDLE  ProcessHandle,
	_Inout_ PVOID   *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_    ULONG   FreeType
);

typedef NTSTATUS (*NTTERMINATEPROCESS)(IN HANDLE ProcessHandle,IN NTSTATUS ExitStatus);
typedef NTSTATUS (*NTISPROCESSINJOB)(_In_ HANDLE ProcessHandle,_In_opt_ HANDLE JobHandle,_Out_ BOOL *Result);
typedef int (*MESSAGEBOXA)(_In_opt_ void *hWnd,_In_opt_ LPCSTR lpText,_In_opt_ LPCSTR lpCaption,_In_ UINT uType);

SYSTEM_SERVICE_TABLE * GetKeServiceDescriptorTable();
SYSTEM_SERVICE_TABLE * GetKeServiceDescriptorTableShadow();
bool GetModuleInformation(SYSTEM_MODULE_INFORMATION_ENTRY * ModuleEntry);
char * OpenFile(wchar_t * name);
void * GetProcAddress(void * hInstance,char * name);
void * GetProcAddressFromFile(void * hInstance,char * name);
void * GetSSDTFunctionAddress(long *KiServiceTable,unsigned long index);
void * GetSSDTFunctionOriginalAddress(void * NtBase,long * KiServiceTable,char * ntoskrnl,unsigned long index);
unsigned long GetSSDTIndex(char *ntdll,char * name);
void * InjectJumpCode(void *NtBase,long *KiServiceTable,char *ntoskrnl,void *HookProcess);
void AntiInjectJumpCode(void * address);
bool HookSSDT(long *KiServiceTable,unsigned long index,void *address);

typedef enum _HOOKNUMBER
{
	HN_NTISPROCESSINJOB,
	HN_NTOPENPROCESS,
	HN_NTTERMINATEPROCESS,
	HN_NTUSERCREATEWINDOWEX,
	HN_MAX
}HOOKNUMBER;

typedef struct _HOOKED
{
	char *Name;
	unsigned long Index;
	bool IsHooked;
	void *HookProcess;
	void *JumpCode;
}HOOKED;

typedef struct _Parameter
{
	void *NtBase;
	void *Win32kBase;
	long *KiServiceTable;
	unsigned long NumberOfSSDT;
	long *KiServiceTableShadow;
	unsigned long NumberOfSSSDT;
	char *ntoskrnl;
	char *ntdll;
	char *win32k;
	HANDLE hProcess;
	HOOKED hooked[HN_MAX];
}Parameter;

extern Parameter *parameter;


typedef struct _MESSAGEBOXCALL
{
	MESSAGEBOXA MessageBoxA;
	void *hWnd;
	LPCSTR lpText;
	LPCSTR lpCaption;
	UINT uType;
}MESSAGEBOXCALL;