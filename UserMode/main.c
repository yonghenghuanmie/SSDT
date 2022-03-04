#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <tchar.h>
#include <windows.h>
#include "ControlCode.h"

HANDLE hProcess;

DWORD ThreadStartRoutine(LPVOID lpThreadParameter)
{
	MSG msg;
	PeekMessage(&msg,NULL,0,0,PM_NOREMOVE);
	BOOL result;
	IsProcessInJob(hProcess,(HANDLE)MessageBoxA,&result);
	return 0;
}

int main()
{
	HANDLE hDevice=CreateFile(_T("\\\\.\\SSDT"),0,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hDevice!=INVALID_HANDLE_VALUE)
	{
		printf("Success to open \\\\.\\SSDT!\n");
		char string[256];
		unsigned long bytes;
		hProcess=OpenProcess(PROCESS_ALL_ACCESS,false,GetCurrentProcessId());
		if(hProcess)
		{
			*(HANDLE*)string=hProcess;
			DeviceIoControl(hDevice,HOOK_INIT,string,sizeof(HANDLE),string,256,&bytes,NULL);
			if(string[0]==1)
			{
				printf("Initialize success!\n");
				DWORD tid;
				CreateThread(NULL,0,ThreadStartRoutine,NULL,0,&tid);
				int NumberOfSSDT=*(int*)(string+1),NumberOfSSSDT=*(int*)(string+sizeof(int)+1);
				int action;
				do
				{
					scanf("%d",&action);
					switch(action)
					{
						case 1:
						{
							SSDTFAT *table=calloc(NumberOfSSDT,sizeof(SSDTFAT));
							unsigned long long hModule=(unsigned long long)GetModuleHandle(_T("ntdll.dll"));
							IMAGE_DOS_HEADER *DosHeader=(IMAGE_DOS_HEADER*)hModule;
							IMAGE_NT_HEADERS *NtHeader=(IMAGE_NT_HEADERS*)(hModule+DosHeader->e_lfanew);
							IMAGE_EXPORT_DIRECTORY *ExportDirectory=(IMAGE_EXPORT_DIRECTORY*)(hModule+NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
							unsigned long *NameTable=(unsigned long*)(hModule+ExportDirectory->AddressOfNames);
							for(int i=0;i<(int)ExportDirectory->NumberOfFunctions;i++)
							{
								char *FunctionName=(char*)(hModule+NameTable[i]);
								if(!strncmp(FunctionName,"Zw",2))
								{
									DeviceIoControl(hDevice,HOOK_LISTSSDT,FunctionName,(unsigned long)strlen(FunctionName)+1,string,256,&bytes,NULL);
									if(string[0]==1)
									{
										unsigned long index=((SSDTFAT*)(string+1))->index;
										table[index]=*(SSDTFAT*)(string+1);
										strcpy(table[index].name,FunctionName);
										table[index].name[0]='N';
										table[index].name[1]='t';
									}
								}
							}
							for(int i=0;i<NumberOfSSDT;i++)
								if(table[i].name[0]==0)
								{
									string[0]=0;
									*(int*)(string+1)=i;
									DeviceIoControl(hDevice,HOOK_LISTSSDT,string,sizeof(int)+sizeof(char),string,256,&bytes,NULL);
									if(string[0]==1)
										table[i]=*(SSDTFAT*)(string+1);
								}
							printf("  %-50s Index     %-18s    OriginalAddress\n","FunctionName","PresentAddress");
							for(int i=0;i<NumberOfSSDT;i++)
								printf("%c %-50s 0x%04X    0x%llX    0x%llX\n",table[i].present==table[i].original?' ':'!',table[i].name,table[i].index,
								(unsigned long long)table[i].present,(unsigned long long)table[i].original);
							free(table);
						}
						break;

						case 2:
							printf("  %-50s Index     %-18s    OriginalAddress\n","FunctionName","PresentAddress");
							for(int i=0;i<NumberOfSSSDT;i++)
							{
								*(int*)string=i;
								DeviceIoControl(hDevice,HOOK_LISTSSSDT,string,sizeof(int),string,256,&bytes,NULL);
								if(string[0]==1)
								{
									SSDTFAT *table=(SSDTFAT*)(string+1);
									printf("%c %-50s 0x%04X    0x%llX    0x%llX\n",table->present==table->original?' ':'!',table->name,table->index+0x1000,
										(unsigned long long)table->present,(unsigned long long)table->original);
								}
							}
							break;
						case 3:
							scanf("%s",string);
							DeviceIoControl(hDevice,UNHOOK_NAME,string,256,string,sizeof(char),&bytes,NULL);
							if(string[0]==1)
								printf("Unhook success!\n");
							break;
						case 4:
							scanf("%x",(int*)string);
							DeviceIoControl(hDevice,UNHOOK_INDEX,string,sizeof(int),string,sizeof(char),&bytes,NULL);
							if(string[0]==1)
								printf("Unhook success!\n");
							break;
						case 5:
							DeviceIoControl(hDevice,HOOK_NTTERMINATEPROCESS,NULL,0,string,sizeof(char),&bytes,NULL);
							if(string[0]==1)
								printf("Hook NtTerminateProcess success!\n");
							break;
						case 6:
							DeviceIoControl(hDevice,UNHOOK_NTTERMINATEPROCESS,NULL,0,string,sizeof(char),&bytes,NULL);
							if(string[0]==1)
								printf("Unhook NtTerminateProcess success!\n");
							break;
						case 7:
							DeviceIoControl(hDevice,HOOK_NTOPENPROCESS,NULL,0,string,sizeof(char),&bytes,NULL);
							if(string[0]==1)
								printf("Hook NtOpenProcess success!\n");
							break;
						case 8:
							DeviceIoControl(hDevice,UNHOOK_NTOPENPROCESS,NULL,0,string,sizeof(char),&bytes,NULL);
							if(string[0]==1)
								printf("Unhook NtOpenProcess success!\n");
							break;
						case 9:
							DeviceIoControl(hDevice,HOOK_NTUSERCREATEWINDOWEX,NULL,0,string,sizeof(char),&bytes,NULL);
							if(string[0]==1)
								printf("Hook NtUserCreateWindowEx success!\n");
							break;
						case 10:
							DeviceIoControl(hDevice,UNHOOK_NTUSERCREATEWINDOWEX,NULL,0,string,sizeof(char),&bytes,NULL);
							if(string[0]==1)
								printf("Unhook NtUserCreateWindowEx success!\n");
							break;
					}
				} while(action!=0);
			}
		}
		CloseHandle(hDevice);
	}
	else
		printf("Error code:%d\n",GetLastError());
	system("pause");
	return 0;
}