#include <iostream>
#include <Windows.h>

static BOOL EnablePrivilege(LPCWSTR name) {
	HANDLE hTok;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
		return FALSE;
	TOKEN_PRIVILEGES tp = {};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid)) {
		CloseHandle(hTok);
		return FALSE;
	}
	BOOL ok = AdjustTokenPrivileges(hTok, FALSE, &tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
	CloseHandle(hTok);
	return ok;
}

int main(int argc, char** argv)
{
	HANDLE hProcess, hThread, hFile;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	EnablePrivilege(SE_INCREASE_QUOTA_NAME);

	hFile = CreateFile(L"C:\\Windows\\System32\\notepad.exe", GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open file: %d\n", GetLastError());
		return -1;
	}
	std::cout << "[+] File handle: " << std::hex << hFile << "\n";

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, GetCurrentProcessId());
	if (hProcess == NULL) {
		std::cerr << "[-] Failed to open process\n";
		return 1;
	}
	std::cout << "[+] Process handle: " << std::hex << hProcess << "\n";

	hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, GetCurrentThreadId());
	if (hThread == NULL) {
		std::cerr << "[-] Failed to open thread\n";
		return 1;
	}
	std::cout << "[+] Thread handle: " << std::hex << hThread << "\n";

	// Take our own primary token, duplicate it, and drop integrity to Medium.
	// Because the new token is derived from the caller's own primary token,
	// CreateProcessAsUserW does not require SeAssignPrimaryTokenPrivilege —
	// only SeIncreaseQuotaPrivilege, which admin already has.
	HANDLE hOwnToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hOwnToken)) {
		std::cerr << "[-] OpenProcessToken failed: " << std::dec << GetLastError() << "\n";
		return 1;
	}

	HANDLE hPrimaryToken = NULL;
	if (!DuplicateTokenEx(hOwnToken,
		TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
		NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
		std::cerr << "[-] DuplicateTokenEx failed: " << std::dec << GetLastError() << "\n";
		CloseHandle(hOwnToken);
		return 1;
	}
	CloseHandle(hOwnToken);

	// Lower the integrity level on the duplicated token to Medium (S-1-16-8192).
	SID_IDENTIFIER_AUTHORITY mlAuth = SECURITY_MANDATORY_LABEL_AUTHORITY;
	PSID pMediumSid = NULL;
	if (!AllocateAndInitializeSid(&mlAuth, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &pMediumSid)) {
		std::cerr << "[-] AllocateAndInitializeSid failed: " << std::dec << GetLastError() << "\n";
		CloseHandle(hPrimaryToken);
		return 1;
	}
	TOKEN_MANDATORY_LABEL tml = {};
	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = pMediumSid;
	if (!SetTokenInformation(hPrimaryToken, TokenIntegrityLevel, &tml,
		sizeof(tml) + GetLengthSid(pMediumSid))) {
		std::cerr << "[-] SetTokenInformation(IL=Medium) failed: " << std::dec << GetLastError() << "\n";
		FreeSid(pMediumSid);
		CloseHandle(hPrimaryToken);
		return 1;
	}
	FreeSid(pMediumSid);

	// Use cmd.exe (classic Win32) instead of notepad.exe, because on Windows 11
	// notepad.exe is a UWP packaged app whose kernel process object denies
	// PROCESS_DUP_HANDLE — which blocks givemeahand from scanning it.
	// CREATE_SUSPENDED keeps the entry point from running; CREATE_NO_WINDOW
	// hides the console. The process exists solely to hold the leaked handles.
	//
	// Give the child process a NULL-DACL security descriptor so any process in
	// the same session can open it for PROCESS_DUP_HANDLE. Without this, the
	// default DACL inherited from the admin token only grants Administrators,
	// and a non-elevated (UAC-split) Medium-IL scanner gets ERROR_ACCESS_DENIED.
	SECURITY_DESCRIPTOR sd;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE); // NULL DACL = full access to everyone
	SECURITY_ATTRIBUTES procAttr = { sizeof(procAttr), &sd, FALSE };

	wchar_t cmd[] = L"C:\\Windows\\System32\\cmd.exe";
	if (!CreateProcessAsUserW(hPrimaryToken, NULL, cmd, &procAttr, NULL, TRUE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		std::cerr << "[-] Failed to create process as user: " << std::dec << GetLastError() << "\n";
		CloseHandle(hPrimaryToken);
		return 1;
	}
	std::cout << "[+] Spawned Medium-IL child PID: " << std::dec << pi.dwProcessId << "\n";
	CloseHandle(hPrimaryToken);
	SuspendThread(hThread);
	return 0;
}
