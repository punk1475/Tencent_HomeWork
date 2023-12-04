// TencentProj.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "windows.h"
#include <iostream>
#include "tlhelp32.h"
#include "assert.h"
#include "psapi.h"
#define PATH_MAX_LENGTH 260
#define CRACKME_PATH "C:\\Users\\25807\\source\\repos\\TencentProj\\x64\\crackme.exe"
#define MYDLL_PATH "C:\\Users\\25807\\source\\repos\\myDll\\x64\\Debug\\myDll.dll"
bool processExists(WCHAR filePath[], DWORD& pid) {
   HANDLE hSnapshot= CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,NULL);
   assert(hSnapshot != INVALID_HANDLE_VALUE);
   PROCESSENTRY32 process;
   PROCESSENTRY32* pProcess = &process;
   pProcess->dwSize = sizeof(PROCESSENTRY32);
   bool flag=Process32First(hSnapshot, pProcess);
   while (flag) {
       HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pProcess->th32ProcessID);
       WCHAR path[PATH_MAX_LENGTH];
       LPWSTR pPath = path;
       if (hProcess&& hProcess != INVALID_HANDLE_VALUE) {
           GetModuleFileNameExW(hProcess, NULL, pPath, PATH_MAX_LENGTH);
           assert(CloseHandle(hProcess));
           if (!lstrcmpW(filePath, pPath)) {
               pid = pProcess->th32ProcessID;
               return true;
           }
       }
       flag = Process32Next(hSnapshot, pProcess);
   }
   return false;
}


int main(int args,char** agrc)
{
    WCHAR filePath[] = TEXT(CRACKME_PATH);
    DWORD pid = 0;
    WCHAR dllPath[] = TEXT(MYDLL_PATH);
    if (processExists(filePath, pid)) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        WriteProcessMemory(hProcess, allocatedMem, dllPath, sizeof(dllPath), NULL);
        CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibrary, allocatedMem, NULL, NULL);
        CloseHandle(hProcess);
    }
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
