
#include "myHook.h"
#include "pch.h"
#include "stdio.h"
#include "detours.h"
#include "windows.h"
#include "psapi.h"
#include "string.h"

#define CODE_BYTE 12
#define MODULE_NAME "myDll.dll"
static int (WINAPI* OldWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;


int WINAPI newWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
	if (hFile == GetStdHandle(STD_OUTPUT_HANDLE)) {
		char* p = (char*)lpBuffer;
		char checkBuf[260];
		for (int i = 0; i < nNumberOfBytesToWrite; i++) {
			checkBuf[i] = p[i];
		}
		checkBuf[nNumberOfBytesToWrite] = '\x00';
		if (strstr(checkBuf,"����")) {
			lpBuffer = "��ȷ";
			nNumberOfBytesToWrite = sizeof("��ȷ");
		}
	}
	return OldWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}


void hookWithLib() {
	if (DetourTransactionBegin() == NO_ERROR) {
		if (DetourUpdateThread(GetCurrentThread()) == NO_ERROR) {
			if (DetourAttach(&(PVOID&)OldWriteFile, newWriteFile) == NO_ERROR) {
			//if (DetourAttach(&(PVOID&)OldReadFile, newReadFile) == NO_ERROR) {
				if (DetourTransactionCommit() == NO_ERROR) {
					MessageBox(NULL, TEXT("hook�ɹ���"), TEXT("hook��ʾ��"), NULL);
				}
				else {
					printf("DetourTransactionCommit Error!\n");
				}
			}
			else {
				printf("DetourAttach Error!\n");
			}
		}
		else
		{
			printf("DetourUpdateThread Error!\n");
		}
	}
	else {
		printf("DetourTransactionBegin Error!\n");
	}
}

class MyHookCls {
	char copy[CODE_BYTE];
	char hookCode[CODE_BYTE];
	INT64 oldFuncAddr;
	INT64 newFuncAddr;
	size_t count;
public:
	MyHookCls(INT64 oldAddr, INT64 newAddr) {
		oldFuncAddr = oldAddr;
		newFuncAddr = newAddr;
		DWORD oldProtect;
		VirtualProtect((LPVOID)oldFuncAddr, CODE_BYTE, PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy((char*)copy, (char*)oldFuncAddr, CODE_BYTE);
		VirtualProtect((LPVOID)oldAddr, CODE_BYTE, oldProtect, &oldProtect);
		//mov rax,��ַ������
		hookCode[0] = '\x48';
		hookCode[1] = '\xb8';
		*(INT64*)(hookCode + 2) = newFuncAddr;
		//push rax
		hookCode[10] = '\x50';
		//ret
		hookCode[11] = '\xc3';
		MessageBox(NULL, TEXT("hook�ɹ���"), TEXT("hook��ʾ��"), NULL);
	}

	//���ڽ�hook����
	void hook() {
		DWORD oldProtect;
		VirtualProtect((LPVOID)oldFuncAddr, CODE_BYTE, PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy((char*)oldFuncAddr, hookCode, CODE_BYTE);
		VirtualProtect((LPVOID)oldFuncAddr, CODE_BYTE, oldProtect, &oldProtect);
	}
	//�ڲ���Ҫʱ��hookȡ��
	void unhook() {
		DWORD oldProtect;
		VirtualProtect((LPVOID)oldFuncAddr, CODE_BYTE, PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy((char*)oldFuncAddr, copy, CODE_BYTE);
		VirtualProtect((LPVOID)oldFuncAddr, CODE_BYTE, oldProtect, &oldProtect);
	}

};

void myFun(char* str);
typedef void (*pFunc)(char* str);
//ʵ���ǿɱ����������͵�����һ�������ĺ�������
pFunc oldFun = (pFunc)0x00007FF7A9C01020;
MyHookCls myHook = MyHookCls((INT64)oldFun, (INT64)myFun);

void myFun(char* str) {
	
	myHook.unhook();
	if (strstr(str, "����")) {
		str =(char*) "��ȷ";
	}
	oldFun(str);
	myHook.hook();
}







