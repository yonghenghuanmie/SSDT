#include "Hook.h"

extern unsigned char * GetKiSystemCall64();

SYSTEM_SERVICE_TABLE * GetKeServiceDescriptorTable()
{
	unsigned char *address=GetKiSystemCall64();
	if(MmIsAddressValid(address)&&MmIsAddressValid(address+1))
		for(int i=2;i<500;i++)
		{
			if(MmIsAddressValid(address+i)&&*(address+i-2)==0x4C&&*(address+i-1)==0x8D&&*(address+i)==0x15)
				return (SYSTEM_SERVICE_TABLE*)(address+i+5+*(unsigned long*)(address+i+1));
		}
	KdPrintEx(0,0,"Failed to find SSDT!/n");
	return NULL;
}

SYSTEM_SERVICE_TABLE * GetKeServiceDescriptorTableShadow()
{
	unsigned char *address=GetKiSystemCall64();
	if(MmIsAddressValid(address)&&MmIsAddressValid(address+1))
		for(int i=2;i<500;i++)
		{
			if(MmIsAddressValid(address+i)&&*(address+i-2)==0x4C&&*(address+i-1)==0x8D&&*(address+i)==0x1D)
				return (SYSTEM_SERVICE_TABLE*)(address+i+5+*(unsigned long*)(address+i+1));
		}
	KdPrintEx(0,0,"Failed to find SSSDT!/n");
	return NULL;
}

bool GetModuleInformation(SYSTEM_MODULE_INFORMATION_ENTRY *ModuleEntry)
{
	bool success=false;
	ULONG size=0;
	SYSTEM_MODULE_INFORMATION *ModuleInformation=NULL;
	ZwQuerySystemInformation(SystemModuleInformation,ModuleInformation,size,&size);
	ModuleInformation=ExAllocatePool(NonPagedPool,size);
	if(ModuleInformation)
	{
		NTSTATUS status=ZwQuerySystemInformation(SystemModuleInformation,ModuleInformation,size,&size);
		if(NT_SUCCESS(status))
		{
			for(unsigned int i=0;i<ModuleInformation->Count;i++)
				if(!strcmp(ModuleEntry->ImageName,strrchr(ModuleInformation->Module[i].ImageName,'\\')+1))
				{
					*ModuleEntry=ModuleInformation->Module[i];
					success=true;
				}
		}
		ExFreePool(ModuleInformation);
	}
	return success;
}

char * OpenFile(wchar_t *name)
{
	char *buffer=NULL;
	HANDLE hFile;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING FileName;
	RtlInitUnicodeString(&FileName,name);
	InitializeObjectAttributes(&ObjectAttributes,&FileName,OBJ_CASE_INSENSITIVE,NULL,NULL);
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS status=ZwCreateFile(&hFile,FILE_READ_DATA,&ObjectAttributes,&IoStatusBlock,NULL,FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,FILE_OPEN,0,NULL,0);
	if(NT_SUCCESS(status))
	{
		FILE_STANDARD_INFORMATION Information;
		status=ZwQueryInformationFile(hFile,&IoStatusBlock,&Information,sizeof(FILE_STANDARD_INFORMATION),FileStandardInformation);
		if(NT_SUCCESS(status))
		{
			buffer=ExAllocatePool(NonPagedPool,Information.EndOfFile.QuadPart);
			if(buffer)
			{
				LARGE_INTEGER ByteOffset={0};
				status=ZwReadFile(hFile,NULL,NULL,NULL,&IoStatusBlock,buffer,Information.EndOfFile.LowPart,&ByteOffset,NULL);
				if(!NT_SUCCESS(status))
				{
					ExFreePool(buffer);
					buffer=NULL;
				}
			}
		}
		ZwClose(hFile);
	}
	return buffer;
}

void * GetProcAddress(void *hInstance,char *name)
{
	void *address=NULL;
	if(MmIsAddressValid(hInstance))
	{
		unsigned long long hModule=(unsigned long long)hInstance;
		IMAGE_DOS_HEADER *DosHeader=(IMAGE_DOS_HEADER*)hModule;
		IMAGE_NT_HEADERS *NtHeader=(IMAGE_NT_HEADERS*)(hModule+DosHeader->e_lfanew);
		IMAGE_EXPORT_DIRECTORY *ExportDirectory=(IMAGE_EXPORT_DIRECTORY*)(hModule+NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
		unsigned short *OrdinalTable=(unsigned short*)(hModule+ExportDirectory->AddressOfNameOrdinals);
		unsigned long *NameTable=(unsigned long*)(hModule+ExportDirectory->AddressOfNames);
		unsigned long *FunctionTable=(unsigned long*)(hModule+ExportDirectory->AddressOfFunctions);
		for(int i=0;i<(int)ExportDirectory->NumberOfFunctions;i++)
		{
			char *FunctionName=(char*)(hModule+NameTable[i]);
			if(!strcmp(FunctionName,name))
			{
				address=(void*)(hModule+FunctionTable[OrdinalTable[i]]);
				break;
			}
		}
	}
	return address;
}

inline unsigned long VirtualAddressToFileAddress(IMAGE_SECTION_HEADER *SectionHeader,unsigned long RVA)
{
	while(RVA>SectionHeader->VirtualAddress+SectionHeader->SizeOfRawData)
		SectionHeader++;
	return SectionHeader->PointerToRawData+RVA-SectionHeader->VirtualAddress;
}

void * GetProcAddressFromFile(void *hInstance,char *name)
{
	void *address=NULL;
	if(MmIsAddressValid(hInstance))
	{
		unsigned long long hModule=(unsigned long long)hInstance;
		IMAGE_DOS_HEADER *DosHeader=(IMAGE_DOS_HEADER*)hModule;
		IMAGE_NT_HEADERS *NtHeader=(IMAGE_NT_HEADERS*)(hModule+DosHeader->e_lfanew);
		IMAGE_SECTION_HEADER *SectionHeader=(IMAGE_SECTION_HEADER*)(NtHeader+1);
		IMAGE_EXPORT_DIRECTORY *ExportDirectory=
			(IMAGE_EXPORT_DIRECTORY*)(hModule+VirtualAddressToFileAddress(SectionHeader,NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
		unsigned short *OrdinalTable=(unsigned short*)(hModule+VirtualAddressToFileAddress(SectionHeader,ExportDirectory->AddressOfNameOrdinals));
		unsigned long *NameTable=(unsigned long*)(hModule+VirtualAddressToFileAddress(SectionHeader,ExportDirectory->AddressOfNames));
		unsigned long *FunctionTable=(unsigned long*)(hModule+VirtualAddressToFileAddress(SectionHeader,ExportDirectory->AddressOfFunctions));
		for(int i=0;i<(int)ExportDirectory->NumberOfFunctions;i++)
		{
			char *FunctionName=(char*)(hModule+VirtualAddressToFileAddress(SectionHeader,NameTable[i]));
			if(!strcmp(FunctionName,name))
			{
				address=(void*)(hModule+VirtualAddressToFileAddress(SectionHeader,FunctionTable[OrdinalTable[i]]));
				break;
			}
		}
	}
	return address;
}

unsigned long GetSSDTIndex(char *ntdll,char *name)
{
	unsigned long index=0xFFFFFFFF;
	if(MmIsAddressValid(ntdll)&&name[0]=='Z'&&name[1]=='w')
	{
		unsigned char *address=GetProcAddressFromFile(ntdll,name);
		if(address)
		{
			while(*address!=0xB8)
				address++;
			index=*(unsigned long*)++address;
		}
	}
	return index;
}

void * GetSSDTFunctionAddress(long *KiServiceTable,unsigned long index)
{
	if(MmIsAddressValid(KiServiceTable)&&index!=0xFFFFFFFF)
		return (void*)((unsigned long long)KiServiceTable+(KiServiceTable[index]>>4));
	return NULL;
}

void * GetSSDTFunctionOriginalAddress(void *NtBase,long *KiServiceTable,char *ntoskrnl,unsigned long index)
{
	if(MmIsAddressValid(NtBase)&&MmIsAddressValid(KiServiceTable)&&MmIsAddressValid(ntoskrnl)&&index!=0xFFFFFFFF)
	{
		IMAGE_DOS_HEADER *DosHeader=(IMAGE_DOS_HEADER*)ntoskrnl;
		IMAGE_NT_HEADERS *NtHeader=(IMAGE_NT_HEADERS*)(ntoskrnl+DosHeader->e_lfanew);
		IMAGE_SECTION_HEADER *SectionHeader=(IMAGE_SECTION_HEADER*)(NtHeader+1);
		unsigned long long *table=(unsigned long long*)
			(ntoskrnl+VirtualAddressToFileAddress(SectionHeader,(unsigned long)((unsigned long long)KiServiceTable-(unsigned long long)NtBase)));
		return (void*)((unsigned long long)NtBase+table[index]-NtHeader->OptionalHeader.ImageBase);
	}
	return NULL;
}

KIRQL WPOFFx64()
{
	KIRQL irql=KeRaiseIrqlToDpcLevel();
	UINT64 cr0=__readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPONx64(KIRQL irql)
{
	UINT64 cr0=__readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

void * InjectJumpCode(void *NtBase,long *KiServiceTable,char *ntoskrnl,void *HookProcess)
{
	void *A=NULL,*B=NULL;
	if(ntoskrnl)
	{
		A=GetSSDTFunctionOriginalAddress(NtBase,KiServiceTable,ntoskrnl,0);
		B=GetSSDTFunctionOriginalAddress(NtBase,KiServiceTable,ntoskrnl,9);
	}
	else
	{
		A=GetProcAddress(NtBase,"NtReadFile");
		B=GetProcAddress(NtBase,"NtShutdownSystem");
	}
	if(A==NULL||B==NULL)
		return NULL;
	int length=(int)((unsigned long long)B-(unsigned long long)A);
	unsigned char *address;
	if(length<0)
	{
		length*=-1;
		address=(unsigned char *)B;
	}
	else
		address=(unsigned char *)A;

	int i,j;
	for(i=0;i<length;i++)
	{
		for(j=0;j<12;j++)
			if(*(address+i+j)!=0x90)
				break;
		if(j==12)
			break;
	}

	if(i<length)
	{
		unsigned char code[]="\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xE0";
		*(unsigned long long*)&code[2]=(unsigned long long)HookProcess;
		KIRQL irql=WPOFFx64();
		memcpy(address+i,code,12);
		WPONx64(irql);
		return address+i;
	}
	KdPrintEx(0,0,"Failed to find free space!\n");
	return NULL;
}

void AntiInjectJumpCode(void *address)
{
	if(MmIsAddressValid(address))
	{
		KIRQL irql=WPOFFx64();
		for(int i=0;i<12;i++)
			*((unsigned char*)address+i)=0x90;
		WPONx64(irql);
	}
}

bool HookSSDT(long *KiServiceTable,unsigned long index,void *address)
{
	if(MmIsAddressValid(KiServiceTable)&&MmIsAddressValid(address)&&index!=0xFFFFFFFF)
	{
		long offset=(long)((unsigned long long)address-(unsigned long long)KiServiceTable)<<4;
		KIRQL irql=WPOFFx64();
		KiServiceTable[index]=offset;
		WPONx64(irql);
		return true;
	}
	return false;
}