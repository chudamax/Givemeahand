#pragma once

#include <Windows.h>

using namespace std;

BOOL CloneHandle(DWORD ownerPid, HANDLE handle, PHANDLE clonedHandle);
DWORD GetTargetIntegrityLevel(HANDLE hProc);
DWORD GetTargetIntegrityLevel(DWORD pid);
DWORD GetTokenIntegrityLevel(HANDLE hToken);
wstring GetProcName(DWORD pid);