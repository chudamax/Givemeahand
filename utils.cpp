#include <windows.h>

#include <map>
#include <string>
#include <iostream>
#include <TlHelp32.h>

using namespace std;

BOOL CloneHandle(DWORD ownerPid, HANDLE handle, PHANDLE clonedHandle) {
	HANDLE elevatedToken = NULL;
	HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE, false, ownerPid);
	if (hOwner == NULL)
		return FALSE;
	bool result = DuplicateHandle(
		hOwner,
		handle,
		GetCurrentProcess(),
		clonedHandle,
		NULL,
		false,
		DUPLICATE_SAME_ACCESS
	);
	CloseHandle(hOwner);
	return result;
}

// GetTokenIntegrityLevel: query IL directly from a token handle.
// Used for leaked token handles where we don't have (or need) a process handle.
DWORD GetTokenIntegrityLevel(HANDLE hToken) {
	DWORD retLen = 0;
	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &retLen);
	if (retLen == 0) return 0;
	PTOKEN_MANDATORY_LABEL tml = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, retLen);
	if (!tml) return 0;
	if (!GetTokenInformation(hToken, TokenIntegrityLevel, tml, retLen, &retLen)) {
		LocalFree(tml);
		return 0;
	}
	DWORD il = *GetSidSubAuthority(tml->Label.Sid,
		(DWORD)(UCHAR)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1));
	LocalFree(tml);
	return il;
}

DWORD GetTargetIntegrityLevel(HANDLE hProc) {
	HANDLE hToken;
	if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
	{
		CloseHandle(hProc);
		return 0;
	}
	PTOKEN_MANDATORY_LABEL tokenInformation;
	DWORD returnLength;
	DWORD integrityLevel;
	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &returnLength);
	if (returnLength <= 0) {
		CloseHandle(hToken);
		CloseHandle(hProc);
		return 0;
	}
	tokenInformation = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, returnLength);
	if (!GetTokenInformation(hToken, TokenIntegrityLevel, tokenInformation, returnLength, &returnLength)) {
		LocalFree(tokenInformation);
		CloseHandle(hToken);
		CloseHandle(hProc);
		return 0;
	}
	integrityLevel = *GetSidSubAuthority(tokenInformation->Label.Sid,
		(DWORD)(UCHAR)(*GetSidSubAuthorityCount(tokenInformation->Label.Sid) - 1));
	LocalFree(tokenInformation);
	CloseHandle(hToken);
	CloseHandle(hProc);
	return integrityLevel;
}

DWORD GetTargetIntegrityLevel(DWORD pid) {
	HANDLE hProc;
	hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (hProc == NULL)
		return 0;
	return GetTargetIntegrityLevel(hProc);
}

wstring GetProcName(DWORD pid)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);
	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
	{
		return wstring();
	}

	for (BOOL bok = Process32First(processesSnapshot, &processInfo); bok; bok = Process32Next(processesSnapshot, &processInfo))
	{
		if (pid == processInfo.th32ProcessID)
		{
			CloseHandle(processesSnapshot);
			return processInfo.szExeFile;
		}

	}
	CloseHandle(processesSnapshot);
	return wstring();
}