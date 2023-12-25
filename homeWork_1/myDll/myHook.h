
#include <Windows.h>

#pragma comment(lib, "detours.lib")
int WINAPI newWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
void hookWithLib();
class MyHookCls {
public:
	MyHookCls(INT64, INT64);
	void hook();
	void unhook();
};

