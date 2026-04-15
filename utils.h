#pragma once

#include <Windows.h>

using namespace std;

BOOL CloneHandle(DWORD ownerPid, HANDLE handle, PHANDLE clonedHandle);
DWORD GetTargetIntegrityLevel(HANDLE hProc);
DWORD GetTargetIntegrityLevel(DWORD pid);
DWORD GetTokenIntegrityLevel(HANDLE hToken);
wstring GetProcName(DWORD pid);

#ifdef EXPLOIT_ENABLED
DWORD CreatePrivProc(PHANDLE hPrivProc, LPWSTR commandLine);
DWORD ExploitDupHandle(HANDLE hProc, LPWSTR commandLine);
DWORD ExploitThreadImpersonation(HANDLE hThread, LPWSTR commandLine);
DWORD ExploitCreateThread(HANDLE hProc, LPWSTR dllPath);
#endif