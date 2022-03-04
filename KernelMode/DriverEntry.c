#include "Hook.h"
#include "../UserMode/ControlCode.h"

Parameter *parameter;
bool Unhook(int num);

NTSTATUS OpenProcess(__out PHANDLE ProcessHandle,__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,__in_opt PCLIENT_ID ClientId)
{
	return STATUS_ACCESS_DENIED;
}

NTSTATUS TerminateProcess(IN HANDLE ProcessHandle,IN NTSTATUS ExitStatus)
{
	PEPROCESS Process;
	NTSTATUS status = ObReferenceObjectByHandle (ProcessHandle,0,*PsProcessType,KernelMode,&Process,NULL);
	if(NT_SUCCESS(status)&&!_stricmp((char*)PsGetProcessImageFileName(Process),"calc.exe"))
		return STATUS_ACCESS_DENIED;
	NTTERMINATEPROCESS NtTerminateProcess=(NTTERMINATEPROCESS)GetSSDTFunctionOriginalAddress(parameter->NtBase,
		parameter->KiServiceTable,parameter->ntoskrnl,GetSSDTIndex(parameter->ntdll,"ZwTerminateProcess"));
	return NtTerminateProcess(ProcessHandle,ExitStatus);
}

NTSTATUS UserModeCode(MESSAGEBOXCALL *Arguments,unsigned long InputLength)
{
	Arguments->MessageBoxA(Arguments->hWnd,Arguments->lpText,Arguments->lpCaption,Arguments->uType);
	return STATUS_SUCCESS;
}

NTSTATUS IsProcessInJob(_In_ HANDLE ProcessHandle,_In_opt_ HANDLE JobHandle,_Out_ BOOL *Result)
{
	if(ProcessHandle==parameter->hProcess)
	{
		Unhook(HN_NTISPROCESSINJOB);
		KdPrintEx(0,0,"%d\n",PsGetCurrentProcessId());
		__try
		{
			KdPrintEx(0,0,"0x%llX",(long long)JobHandle);
			ProbeForRead(JobHandle,1,1);
			ULONG length;
			PROCESS_BASIC_INFORMATION PBI;
			ZwQueryInformationProcess(ProcessHandle,ProcessBasicInformation,&PBI,sizeof(PBI),&length);
			unsigned long long KernelCallbackTable=*(unsigned long long*)((unsigned long long)PBI.PebBaseAddress+0x58);
			unsigned long long base=(KernelCallbackTable+0x40000000+sizeof(void*)-1)&~(sizeof(void*)-1);
			unsigned char *start=(unsigned char *)UserModeCode;
			while(*start!=0xC3)
				start++;
			SIZE_T CodeSize=start-(unsigned char *)UserModeCode+1,
				size=sizeof(void*)+CodeSize+strlen("This Message From Kernel!")+1+strlen("Kernel")+1;
			NTSTATUS status=ZwAllocateVirtualMemory(ZwCurrentProcess(),(void**)&base,0,&size,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
			if(NT_SUCCESS(status))
			{
				MESSAGEBOXCALL MessageBoxCall;
				MessageBoxCall.MessageBoxA=JobHandle;
				MessageBoxCall.hWnd=NULL;
				MessageBoxCall.uType=0;
				unsigned long long temp=base+sizeof(void*);
				*(unsigned long long*)base=temp;
				memcpy((void*)temp,(void*)UserModeCode,CodeSize);
				temp+=CodeSize;
				MessageBoxCall.lpCaption=strcpy((char*)temp,"Kernel");
				temp+=strlen("Kernel")+1;
				MessageBoxCall.lpText=strcpy((char*)temp,"This Message From Kernel!");

				void *OutputBuffer;
				unsigned long OutputLength;
				//FuncAddr= KernelCallbackTable + ApiNumber*sizeof(PVOID);
				status=KeUserModeCallback((unsigned long)(base-KernelCallbackTable)/sizeof(void*),&MessageBoxCall,
					sizeof(MESSAGEBOXCALL),&OutputBuffer,&OutputLength);
				ZwFreeVirtualMemory(ZwCurrentProcess(),(void**)&base,&size,MEM_RELEASE);
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER){}
	}
	else
	{
		NTISPROCESSINJOB NtIsProcessInJob=(NTISPROCESSINJOB)GetSSDTFunctionOriginalAddress(parameter->NtBase,
			parameter->KiServiceTable,parameter->ntoskrnl,GetSSDTIndex(parameter->ntdll,"ZwIsProcessInJob"));
		return NtIsProcessInJob(ProcessHandle,JobHandle,Result);
	}
	return STATUS_SUCCESS;
}

bool Hook(int num)
{
	if(parameter->hooked[num].Name)
	{
		parameter->hooked[num].JumpCode=InjectJumpCode(parameter->NtBase,NULL,NULL,parameter->hooked[num].HookProcess);
		if(HookSSDT(parameter->KiServiceTable,GetSSDTIndex(parameter->ntdll,parameter->hooked[num].Name),parameter->hooked[num].JumpCode))
		{
			parameter->hooked[num].IsHooked=true;
			return true;
		}
	}
	else
	{
		parameter->hooked[num].JumpCode=InjectJumpCode(parameter->Win32kBase,
			parameter->KiServiceTableShadow,parameter->win32k,parameter->hooked[num].HookProcess);
		if(HookSSDT(parameter->KiServiceTableShadow,parameter->hooked[num].Index,parameter->hooked[num].JumpCode))
		{
			parameter->hooked[num].IsHooked=true;
			return true;
		}
	}
	return false;
}

bool Unhook(int num)
{
	if(parameter->hooked[num].IsHooked)
	{
		void *base;
		long *table;
		char *file;
		unsigned long index;
		if(parameter->hooked[num].Name)
		{
			base=parameter->NtBase;
			table=parameter->KiServiceTable;
			file=parameter->ntoskrnl;
			index=GetSSDTIndex(parameter->ntdll,parameter->hooked[num].Name);
		}
		else
		{
			base=parameter->Win32kBase;
			table=parameter->KiServiceTableShadow;
			file=parameter->win32k;
			index=parameter->hooked[num].Index;
		}
		if(HookSSDT(table,index,GetSSDTFunctionOriginalAddress(base,table,file,index)))
		{
			parameter->hooked[num].IsHooked=false;
			AntiInjectJumpCode(parameter->hooked[num].JumpCode);
			parameter->hooked[num].JumpCode=NULL;
			return true;
		}
	}
	else
		return true;
	return false;
}

void DriverUnload(DRIVER_OBJECT *DriverObject)
{
	for(int i=0;i<HN_MAX;i++)
		Unhook(i);
	if(parameter->ntoskrnl)
	{
		ExFreePool(parameter->ntoskrnl);
		parameter->ntoskrnl=NULL;
	}
	if(parameter->ntdll)
	{
		ExFreePool(parameter->ntdll);
		parameter->ntdll=NULL;
	}
	if(parameter->win32k)
	{
		ExFreePool(parameter->win32k);
		parameter->win32k=NULL;
	}
	UNICODE_STRING SymbolicLinkName;
	RtlInitUnicodeString(&SymbolicLinkName,L"\\??\\SSDT");
	IoDeleteSymbolicLink(&SymbolicLinkName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DeviceIoControl(DEVICE_OBJECT *DeviceObject,IRP *Irp)
{
	NTSTATUS status=STATUS_UNSUCCESSFUL;
	IO_STACK_LOCATION *stack=IoGetCurrentIrpStackLocation(Irp);
	ULONG IoControlCode=stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG InputLength=stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG OutputLength=stack->Parameters.DeviceIoControl.OutputBufferLength;
	char *buffer=Irp->AssociatedIrp.SystemBuffer;
	ULONG size=sizeof(char);
	HOOKNUMBER num;
	unsigned long index;
	switch(IoControlCode)
	{
		case HOOK_INIT:
			if(parameter->NtBase==NULL)
			{
				wchar_t FileName[256]=L"\\SystemRoot\\system32\\";
				wcscat(FileName,L"ntoskrnl.exe");
				parameter->ntoskrnl=OpenFile(FileName);
				FileName[wcslen(FileName)-wcslen(L"ntoskrnl.exe")]=0;
				wcscat(FileName,L"ntdll.dll");
				parameter->ntdll=OpenFile(FileName);
				FileName[wcslen(FileName)-wcslen(L"ntdll.dll")]=0;
				wcscat(FileName,L"win32k.sys");
				parameter->win32k=OpenFile(FileName);
				if(parameter->ntoskrnl&&parameter->ntdll&&parameter->win32k)
				{
					SYSTEM_SERVICE_TABLE * KeServicesDescriptorTable=GetKeServiceDescriptorTable();
					SYSTEM_SERVICE_TABLE * KeServicesDescriptorTableShadow=GetKeServiceDescriptorTableShadow()+1;
					if(KeServicesDescriptorTable&&KeServicesDescriptorTableShadow)
					{
						parameter->KiServiceTable=(long*)KeServicesDescriptorTable->ServiceTableBase;
						parameter->NumberOfSSDT=(unsigned long)KeServicesDescriptorTable->NumberOfServices;
						parameter->KiServiceTableShadow=(long*)KeServicesDescriptorTableShadow->ServiceTableBase;
						parameter->NumberOfSSSDT=(unsigned long)KeServicesDescriptorTableShadow->NumberOfServices;
						SYSTEM_MODULE_INFORMATION_ENTRY ModuleInformation;
						strcpy(ModuleInformation.ImageName,"win32k.sys");
						if(GetModuleInformation(&ModuleInformation))
						{
							parameter->Win32kBase=ModuleInformation.Base;
							strcpy(ModuleInformation.ImageName,/*"ntoskrnl.exe"*/"goodkrnl.exe");
							if(GetModuleInformation(&ModuleInformation))
							{
								parameter->NtBase=ModuleInformation.Base;
								parameter->hProcess=*(HANDLE*)buffer;
								parameter->hooked[HN_NTISPROCESSINJOB].Name="ZwIsProcessInJob";
								parameter->hooked[HN_NTISPROCESSINJOB].HookProcess=(void*)IsProcessInJob;
								if(Hook(HN_NTISPROCESSINJOB))
								{
									parameter->hooked[HN_NTOPENPROCESS].Name="ZwOpenProcess";
									parameter->hooked[HN_NTOPENPROCESS].HookProcess=(void*)OpenProcess;
									parameter->hooked[HN_NTTERMINATEPROCESS].Name="ZwTerminateProcess";
									parameter->hooked[HN_NTTERMINATEPROCESS].HookProcess=(void*)TerminateProcess;
									parameter->hooked[HN_NTUSERCREATEWINDOWEX].Name=NULL;
									parameter->hooked[HN_NTUSERCREATEWINDOWEX].Index=0x76;
									parameter->hooked[HN_NTUSERCREATEWINDOWEX].HookProcess=(void*)OpenProcess;
									*(unsigned long*)(buffer+1)=parameter->NumberOfSSDT;
									*(unsigned long*)(buffer+sizeof(unsigned long)+1)=parameter->NumberOfSSSDT;
									size+=sizeof(unsigned long)*2;
									status=STATUS_SUCCESS;
								}
							}
						}
					}
				}
			}
			else
			{
				if(parameter->hooked[HN_NTISPROCESSINJOB].IsHooked)
					Unhook(HN_NTISPROCESSINJOB);
				if(Hook(HN_NTISPROCESSINJOB))
				{
					parameter->hProcess=*(HANDLE*)buffer;
					*(unsigned long*)(buffer+1)=parameter->NumberOfSSDT;
					*(unsigned long*)(buffer+sizeof(unsigned long)+1)=parameter->NumberOfSSSDT;
					size+=sizeof(unsigned long)*2;
					status=STATUS_SUCCESS;
				}
			}
			break;

		case HOOK_LISTSSDT:
			if(buffer[0])
				index=GetSSDTIndex(parameter->ntdll,buffer);
			else
				index=*(unsigned long*)(buffer+1);
			if(index!=0xFFFFFFFF)
			{
				SSDTFAT *table=(SSDTFAT*)(buffer+1);
				table->name[0]=0;
				table->index=index;
				table->present=GetSSDTFunctionAddress(parameter->KiServiceTable,index);
				table->original=GetSSDTFunctionOriginalAddress(parameter->NtBase,parameter->KiServiceTable,parameter->ntoskrnl,index);
				size+=sizeof(SSDTFAT);
				status=STATUS_SUCCESS;
			}
			break;

		case HOOK_LISTSSSDT:
			index=*(unsigned long*)buffer;
			if(index!=0xFFFFFFFF)
			{
				SSDTFAT *table=(SSDTFAT*)(buffer+1);
				table->name[0]=0;
				table->index=index;
				table->present=GetSSDTFunctionAddress(parameter->KiServiceTableShadow,index);
				table->original=GetSSDTFunctionOriginalAddress(parameter->Win32kBase,parameter->KiServiceTableShadow,parameter->win32k,index);
				size+=sizeof(SSDTFAT);
				status=STATUS_SUCCESS;
			}
			break;

		case UNHOOK_NAME:
			index=GetSSDTIndex(parameter->ntdll,buffer);
			if(HookSSDT(parameter->KiServiceTable,index,
				GetSSDTFunctionOriginalAddress(parameter->NtBase,parameter->KiServiceTable,parameter->ntoskrnl,index)))
				status=STATUS_SUCCESS;
			break;

		case UNHOOK_INDEX:
		{
			void *base;
			long *table;
			char *file;
			index=*(unsigned long*)buffer;
			if(index<0x1000)
			{
				base=parameter->NtBase;
				table=parameter->KiServiceTable;
				file=parameter->ntoskrnl;
			}
			else
			{
				base=parameter->Win32kBase;
				table=parameter->KiServiceTableShadow;
				file=parameter->win32k;
				index-=0x1000;
			}
			if(HookSSDT(table,index,GetSSDTFunctionOriginalAddress(base,table,file,index)))
				status=STATUS_SUCCESS;
		}
		break;

		case HOOK_NTOPENPROCESS:
			num=HN_NTOPENPROCESS;
		case HOOK_NTTERMINATEPROCESS:
			if(IoControlCode==HOOK_NTTERMINATEPROCESS)
				num=HN_NTTERMINATEPROCESS;
		case HOOK_NTUSERCREATEWINDOWEX:
			if(IoControlCode==HOOK_NTUSERCREATEWINDOWEX)
				num=HN_NTUSERCREATEWINDOWEX;
			if(parameter->hooked[num].IsHooked)
				Unhook(num);
			if(Hook(num))
				status=STATUS_SUCCESS;
			else
				Unhook(num);
			break;

		case UNHOOK_NTOPENPROCESS:
			num=HN_NTOPENPROCESS;
		case UNHOOK_NTTERMINATEPROCESS:
			if(IoControlCode==UNHOOK_NTTERMINATEPROCESS)
				num=HN_NTTERMINATEPROCESS;
		case UNHOOK_NTUSERCREATEWINDOWEX:
			if(IoControlCode==UNHOOK_NTUSERCREATEWINDOWEX)
				num=HN_NTUSERCREATEWINDOWEX;
			if(Unhook(num))
				status=STATUS_SUCCESS;
			break;

		default:
			status=STATUS_INVALID_DEVICE_REQUEST;
	}
	ASSERT(size<=OutputLength);
	if(NT_SUCCESS(status))
		*buffer=true;
	else
		*buffer=false;
	Irp->IoStatus.Information=size;
	Irp->IoStatus.Status=status;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	return status;
}

NTSTATUS DeviceClose(DEVICE_OBJECT *DeviceObject,IRP *Irp)
{
	Irp->IoStatus.Status=STATUS_SUCCESS;
	Irp->IoStatus.Information=0;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceCreate(DEVICE_OBJECT *DeviceObject,IRP *Irp)
{
	Irp->IoStatus.Status=STATUS_SUCCESS;
	Irp->IoStatus.Information=0;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(DRIVER_OBJECT *DriverObject,UNICODE_STRING *RegistryPath)
{
	DriverObject->MajorFunction[IRP_MJ_CREATE]=DeviceCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]=DeviceClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=DeviceIoControl;
	DriverObject->DriverUnload=DriverUnload;
	UNICODE_STRING DeviceName;
	RtlInitUnicodeString(&DeviceName,L"\\Device\\SSDTDevice");
	DEVICE_OBJECT *DeviceObject;
	NTSTATUS status=IoCreateDevice(DriverObject,sizeof(Parameter),&DeviceName,FILE_DEVICE_UNKNOWN,0,FALSE,&DeviceObject);
	if(NT_SUCCESS(status))
	{
		parameter=(Parameter*)DeviceObject->DeviceExtension;
		UNICODE_STRING SymbolicLinkName;
		RtlInitUnicodeString(&SymbolicLinkName,L"\\??\\SSDT");
		status=IoCreateSymbolicLink(&SymbolicLinkName,&DeviceName);
		if(NT_SUCCESS(status))
			return STATUS_SUCCESS;
		IoDeleteDevice(DeviceObject);
	}
	return status;
}