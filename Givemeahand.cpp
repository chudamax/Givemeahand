// Givemeahand.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <TlHelp32.h>
#include <map>
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

using fNtQueryObject = NTSTATUS(WINAPI*)(
	HANDLE Handle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _OBJECT_TYPE_INFORMATION_LOCAL {
	UNICODE_STRING TypeName;
	ULONG Reserved[22];
} OBJECT_TYPE_INFORMATION_LOCAL, * POBJECT_TYPE_INFORMATION_LOCAL;

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
	cout <<
		"Givemeahand: leaked-handle privilege-escalation scanner\n"
		"Refs: https://aptw.tf/2022/02/10/leaked-handle-hunting.html\n"
		"      http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/\n"
		"\n"
		"Detection filter (default = STRICT):\n"
		"  Process: PROCESS_ALL_ACCESS, PROCESS_CREATE_PROCESS,\n"
		"           or (PROCESS_CREATE_THREAD & PROCESS_VM_WRITE).\n"
		"  Thread:  THREAD_ALL_ACCESS or THREAD_DIRECT_IMPERSONATION.\n"
		"  Token:   TOKEN_DUPLICATE or TOKEN_ASSIGN_PRIMARY.\n"
		"  + Target must be alive, not the holder itself, and at an IL\n"
		"    strictly > the scanner's own (and >= High).\n"
		"\n"
		"Flags:\n"
		"  --loose              Include weaker rights (DUP_HANDLE, SET_CONTEXT, IMPERSONATE)\n"
		"  --all                Disable all filtering, show every handle of interest\n"
		"  --pid <N>            Diagnostic: dump all handles owned by PID N\n"
		"  --trace-pid <N>      Diagnostic: trace clone/IL checks for PID N\n"
		"\n"
		"Examples:\n"
		"  .\\Givemeahand                    (strict scan, default)\n"
		"  .\\Givemeahand --loose             (include noisier hits)\n"
		;
}

void printHandleInfo(SYSTEM_HANDLE_TABLE_ENTRY_INFO& handle, const DWORD& integrityLevel,
	DWORD targetPid = 0, const wchar_t* primitive = nullptr)
{
	std::wcout << L"[!] HOLDER: " << GetProcName(handle.UniqueProcessId)
		<< L" (" << std::dec << handle.UniqueProcessId << L")\n\t"
		<< L"|_ Handle value:  0x" << std::hex << static_cast<uint64_t>(handle.HandleValue) << L"\n\t"
		<< L"|_ Object type:   0x" << std::hex << static_cast<uint32_t>(handle.ObjectTypeNumber) << L"\n\t"
		<< L"|_ Access granted: 0x" << std::hex << static_cast<uint32_t>(handle.GrantedAccess) << L"\n\t";
	if (targetPid) {
		std::wcout << L"|_ TARGET: " << GetProcName(targetPid)
			<< L" (" << std::dec << targetPid << L") IL=0x" << std::hex << integrityLevel << L"\n\t";
	} else {
		std::wcout << L"|_ Target IL:     0x" << std::hex << integrityLevel << L"\n\t";
	}
	if (primitive) std::wcout << L"|_ Primitive:     " << primitive << L"\n\t";
	std::wcout << std::endl;
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

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	PROCESSENTRY32W processEntry = { 0 };
	THREADENTRY32 threadEntry = { 0 };
	processEntry.dwSize = sizeof(PROCESSENTRY32W);
	threadEntry.dwSize = sizeof(THREADENTRY32);
	vector<DWORD> pids = {};

	std::cout << "[*] Populating tid2pid map ..." << endl;
	map<DWORD, DWORD> tid2pid = {};

	auto status = Thread32First(snapshot, &threadEntry);
	do
	{
		tid2pid[threadEntry.th32ThreadID] = threadEntry.th32OwnerProcessID;
	} while (Thread32Next(snapshot, &threadEntry));
	CloseHandle(snapshot);


	// Pre-open own-type handles so they show up in the system handle snapshot
	// below. Used after the snapshot to resolve ObjectTypeNumber -> type name
	// for Process/Thread/Token (replacing the stale OB_TYPE_INDEX_* constants).
	HANDLE hOwnProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
	HANDLE hOwnThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentThreadId());
	HANDLE hOwnTok = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hOwnTok);

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

	// Diagnostic: histogram of ObjectTypeNumber values seen across the whole
	// handle table, plus optional per-PID dump via --pid <N>.
	uint32_t idxProcess = 0, idxThread = 0, idxToken = 0;
	{
		std::map<uint32_t, uint32_t> typeHist;
		for (uint32_t i = 0; i < handleInfo->HandleCount; i++)
			typeHist[handleInfo->Handles[i].ObjectTypeNumber]++;
		// Resolve ObjectTypeNumber -> type name. First pass walks our own
		// handles; second pass opens known-type handles (process/thread/token
		// on ourselves) so Process/Thread/Token indices always get resolved
		// even if the first pass misses them.
		fNtQueryObject NtQueryObject = (fNtQueryObject)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQueryObject");
		DWORD ownPid = GetCurrentProcessId();
		std::map<uint32_t, std::wstring> typeName;
		BYTE tbuf[2048];
		for (uint32_t i = 0; i < handleInfo->HandleCount; i++) {
			auto& h = handleInfo->Handles[i];
			if (h.UniqueProcessId != ownPid) continue;
			if (typeName.count(h.ObjectTypeNumber)) continue;
			ULONG ret = 0;
			if (NtQueryObject((HANDLE)h.HandleValue, 2 /*ObjectTypeInformation*/,
				tbuf, sizeof(tbuf), &ret) == 0) {
				auto* info = (POBJECT_TYPE_INFORMATION_LOCAL)tbuf;
				typeName[h.ObjectTypeNumber] = std::wstring(info->TypeName.Buffer,
					info->TypeName.Length / sizeof(WCHAR));
			}
		}

		// Second pass: force-open known-type handles so we can reliably
		// discover their runtime ObjectTypeNumber from the handle table.
		auto resolveOwnHandle = [&](HANDLE h) {
			if (!h || h == INVALID_HANDLE_VALUE) return;
			ULONG ret = 0;
			if (NtQueryObject(h, 2, tbuf, sizeof(tbuf), &ret) != 0) return;
			auto* info = (POBJECT_TYPE_INFORMATION_LOCAL)tbuf;
			std::wstring name(info->TypeName.Buffer, info->TypeName.Length / sizeof(WCHAR));
			// Find the matching entry in the handle table so we can learn its TypeNumber.
			for (uint32_t i = 0; i < handleInfo->HandleCount; i++) {
				auto& he = handleInfo->Handles[i];
				if (he.UniqueProcessId == ownPid && (HANDLE)he.HandleValue == h) {
					typeName[he.ObjectTypeNumber] = name;
					break;
				}
			}
		};
		resolveOwnHandle(hOwnProc);
		resolveOwnHandle(hOwnThread);
		resolveOwnHandle(hOwnTok);
		if (hOwnProc) CloseHandle(hOwnProc);
		if (hOwnThread) CloseHandle(hOwnThread);
		if (hOwnTok) CloseHandle(hOwnTok);

		std::cout << "[*] ObjectTypeNumber histogram:\n";
		for (auto& kv : typeHist) {
			std::wcout << L"    0x" << std::hex << kv.first
				<< L" -> " << std::dec << kv.second
				<< L"  " << (typeName.count(kv.first) ? typeName[kv.first] : L"?") << L"\n";
		}

		// Resolve the four indices we care about from the discovered type names.
		// These replace the stale compile-time OB_TYPE_INDEX_* constants in support.h.
		for (auto& kv : typeName) {
			if (kv.second == L"Process") idxProcess = kv.first;
			else if (kv.second == L"Thread") idxThread = kv.first;
			else if (kv.second == L"Token") idxToken = kv.first;
		}
		std::cout << "[*] Resolved indices: Process=0x" << std::hex << idxProcess
			<< " Thread=0x" << idxThread << " Token=0x" << idxToken << std::dec << "\n";
		if (!idxProcess || !idxThread) {
			std::cerr << "[-] Failed to resolve Process/Thread type index — aborting\n";
			return 1;
		}

		if (args.count(L"--pid")) {
			DWORD filterPid = _wtoi(args.find(L"--pid")->second.c_str());
			std::cout << "[*] Dumping all handles owned by PID " << std::dec << filterPid << ":\n";
			uint32_t shown = 0;
			for (uint32_t i = 0; i < handleInfo->HandleCount; i++) {
				auto& h = handleInfo->Handles[i];
				if (h.UniqueProcessId == filterPid) {
					std::cout << "    handle=0x" << std::hex << h.HandleValue
						<< " type=0x" << (uint32_t)h.ObjectTypeNumber
						<< " access=0x" << h.GrantedAccess << "\n";
					shown++;
				}
			}
			std::cout << "[*] Total handles for PID " << std::dec << filterPid << ": " << shown << "\n";
		}
	}

	DWORD tracePid = args.count(L"--trace-pid") ? _wtoi(args.find(L"--trace-pid")->second.c_str()) : 0;

	// Resolve the scanner's own integrity level once so we can require
	// TARGET_IL > OWN_IL rather than just >= High. Otherwise a Medium-IL
	// scanner would flag handles whose targets are also Medium.
	DWORD ownIL = GetTargetIntegrityLevel(GetCurrentProcessId());
	std::cout << "[*] Scanner IL: 0x" << std::hex << ownIL << std::dec << "\n";

	// Default filter is STRICT — only report handles whose GrantedAccess maps
	// to a concrete, practically-exploitable LPE primitive:
	//   Process: PROCESS_ALL_ACCESS, PROCESS_CREATE_PROCESS,
	//            or (PROCESS_CREATE_THREAD & PROCESS_VM_WRITE).
	//            Bare PROCESS_DUP_HANDLE is excluded — in practice, modern
	//            sandboxed IPC holds DUP_HANDLE-only handles on non-privileged
	//            peers, which rarely lead to useful escalation. Opt in with --loose.
	//   Thread:  THREAD_ALL_ACCESS or THREAD_DIRECT_IMPERSONATION.
	//            Bare SET_CONTEXT / SUSPEND_RESUME excluded — not actionable alone.
	//   Token:   TOKEN_DUPLICATE or TOKEN_ASSIGN_PRIMARY.
	//            Bare TOKEN_IMPERSONATE excluded — can't convert to primary token
	//            without DUPLICATE, so not a direct process-creation primitive.
	//
	// Additional filters applied after the access-mask check:
	//   - Target process/thread must be alive (GetProcessId returns non-zero).
	//   - Target IL must be strictly > scanner's own IL (real privesc, not lateral).
	//   - Target must not be the owner itself (self-handles aren't useful).
	//   - ACCESS_DENIED on the IL query no longer auto-passes — it usually just
	//     means the target died or we hit a stale handle from a dead parent.
	//
	// --loose reverts to the original broader filter (includes DUP_HANDLE etc).
	// --all turns all filtering off — show everything Process/Thread/Token.
	bool looseMode = args.count(L"--loose") > 0;
	bool showAll = args.count(L"--all") > 0;

	auto isExploitableProcessStrict = [](ULONG a) {
		if (a == PROCESS_ALL_ACCESS) return true;
		if (a & PROCESS_CREATE_PROCESS) return true;
		if ((a & PROCESS_CREATE_THREAD) && (a & PROCESS_VM_WRITE)) return true;
		return false;
	};
	auto isExploitableProcessLoose = [](ULONG a) {
		return a == PROCESS_ALL_ACCESS ||
			(a & PROCESS_CREATE_PROCESS) ||
			(a & PROCESS_CREATE_THREAD) ||
			(a & PROCESS_DUP_HANDLE) ||
			(a & PROCESS_VM_OPERATION) ||
			(a & PROCESS_VM_WRITE);
	};
	auto isExploitableThreadStrict = [](ULONG a) {
		if (a == THREAD_ALL_ACCESS) return true;
		if (a & THREAD_DIRECT_IMPERSONATION) return true;
		return false;
	};
	auto isExploitableThreadLoose = [](ULONG a) {
		return a == THREAD_ALL_ACCESS ||
			(a & THREAD_DIRECT_IMPERSONATION) ||
			(a & THREAD_SET_CONTEXT) ||
			(a & THREAD_SUSPEND_RESUME);
	};
	auto isExploitableTokenStrict = [](ULONG a) {
		return (a & TOKEN_DUPLICATE) || (a & TOKEN_ASSIGN_PRIMARY);
	};
	auto isExploitableTokenLoose = [](ULONG a) {
		return (a & TOKEN_IMPERSONATE) || (a & TOKEN_DUPLICATE) || (a & TOKEN_ASSIGN_PRIMARY);
	};
	for (uint32_t i = 0; i < handleInfo->HandleCount; i++)
	{
		auto handle = handleInfo->Handles[i];
		uint32_t t = handle.ObjectTypeNumber;
		if (tracePid && handle.UniqueProcessId == tracePid &&
			(t == idxProcess || t == idxThread || t == idxToken)) {
			std::cout << "[trace] pid=" << std::dec << handle.UniqueProcessId
				<< " handle=0x" << std::hex << handle.HandleValue
				<< " type=0x" << t << " access=0x" << handle.GrantedAccess;
			HANDLE cl = NULL;
			SetLastError(0);
			HANDLE hOwnerDbg = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.UniqueProcessId);
			DWORD openErr = GetLastError();
			BOOL dupOk = FALSE;
			DWORD dupErr = 0;
			if (hOwnerDbg) {
				dupOk = DuplicateHandle(hOwnerDbg, (HANDLE)handle.HandleValue,
					GetCurrentProcess(), &cl, 0, FALSE, DUPLICATE_SAME_ACCESS);
				dupErr = GetLastError();
				CloseHandle(hOwnerDbg);
			}
			BOOL cloneOk = (hOwnerDbg && dupOk);
			std::cout << " openOwner=" << (hOwnerDbg ? "ok" : "FAIL") << "(err=" << std::dec << openErr << ")"
				<< " dup=" << (dupOk ? "ok" : "FAIL") << "(err=" << dupErr << ")";
			if (cloneOk) {
				DWORD il = 0;
				if (t == idxProcess) il = GetTargetIntegrityLevel(cl);
				else if (t == idxThread) {
					DWORD tid = GetThreadId(cl);
					il = tid ? GetTargetIntegrityLevel(tid2pid[tid]) : 0;
				}
				else il = GetTokenIntegrityLevel(cl);
				std::cout << " IL=0x" << il << " lastErr=" << std::dec << GetLastError();
			}
			std::cout << "\n";
		}
		if (t == idxProcess) goto process_branch;
		else if (t == idxThread) goto thread_branch;
		else if (idxToken && t == idxToken) goto token_branch;
		else continue;
		switch (0)
		{
		process_branch:
		{
			bool matchProc = showAll ? true :
				(looseMode ? isExploitableProcessLoose(handle.GrantedAccess)
				           : isExploitableProcessStrict(handle.GrantedAccess));
			if (matchProc) {
				HANDLE clHandle;
				try
				{
					if (CloneHandle(handle.UniqueProcessId, (HANDLE)handle.HandleValue, &clHandle)) {
						// Verify the target is actually a live process. Kernel
						// keeps EPROCESS alive as long as any handle references
						// it, so GetProcessId returns a non-zero PID even for
						// zombies. Use the CreateToolhelp32Snapshot-backed
						// GetProcName — it only resolves a name for procs still
						// listed by the kernel's process list.
						DWORD targetPid = GetProcessId(clHandle);
						DWORD integrityLevel = GetTargetIntegrityLevel(clHandle);
						std::wstring targetName = targetPid ? GetProcName(targetPid) : L"";
						bool alive = (targetPid != 0 && !targetName.empty());
						bool notSelf = (targetPid != handle.UniqueProcessId);
						bool privesc = (integrityLevel > ownIL && integrityLevel >= SECURITY_MANDATORY_HIGH_RID);
						const wchar_t* prim = nullptr;
						ULONG ga = handle.GrantedAccess;
						if (ga == PROCESS_ALL_ACCESS) prim = L"ALL_ACCESS -> parent-spoof primitive";
						else if (ga & PROCESS_CREATE_PROCESS) prim = L"CREATE_PROCESS -> parent-spoof primitive";
						else if ((ga & PROCESS_CREATE_THREAD) && (ga & PROCESS_VM_WRITE)) prim = L"CREATE_THREAD+VM_WRITE -> DLL injection primitive";
						else if (ga & PROCESS_DUP_HANDLE) prim = L"DUP_HANDLE -> handle-table brute force primitive";
						if (showAll || (alive && notSelf && privesc))
						{
							vSysHandle.push_back(handle);
							printHandleInfo(handle, integrityLevel, targetPid, prim);
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
		thread_branch:
		{
			bool matchThread = showAll ? true :
				(looseMode ? isExploitableThreadLoose(handle.GrantedAccess)
				           : isExploitableThreadStrict(handle.GrantedAccess));
			if (matchThread) {
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
						bool notSelf = (pid != handle.UniqueProcessId);
						bool privesc = (integrityLevel > ownIL && integrityLevel >= SECURITY_MANDATORY_HIGH_RID);
						const wchar_t* prim = nullptr;
						ULONG ga = handle.GrantedAccess;
						if (ga == THREAD_ALL_ACCESS) prim = L"THREAD_ALL_ACCESS -> thread impersonation primitive";
						else if (ga & THREAD_DIRECT_IMPERSONATION) prim = L"DIRECT_IMPERSONATION -> thread impersonation";
						if (showAll || (notSelf && privesc))
						{
							vSysHandle.push_back(handle);
							printHandleInfo(handle, integrityLevel, pid, prim);
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

		token_branch:
		{
			bool matchToken = showAll ? true :
				(looseMode ? isExploitableTokenLoose(handle.GrantedAccess)
				           : isExploitableTokenStrict(handle.GrantedAccess));
			if (matchToken) {
				HANDLE clHandle;
				try
				{
					if (CloneHandle(handle.UniqueProcessId, (HANDLE)handle.HandleValue, &clHandle)) {
						DWORD integrityLevel = GetTokenIntegrityLevel(clHandle);
						bool privesc = (integrityLevel > ownIL && integrityLevel >= SECURITY_MANDATORY_HIGH_RID);
						const wchar_t* prim = nullptr;
						ULONG ga = handle.GrantedAccess;
						if ((ga & TOKEN_DUPLICATE) || (ga & TOKEN_ASSIGN_PRIMARY))
							prim = L"TOKEN_DUPLICATE/ASSIGN_PRIMARY -> direct token theft";
						if (showAll || privesc)
						{
							vSysHandle.push_back(handle);
							printHandleInfo(handle, integrityLevel, 0, prim);
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
		}
	}

	std::cout << "[" << (vSysHandle.size() > 0 ? "!" : "*") << "] Found " << vSysHandle.size() << " vulnerable handles\n";
	std::cout << "[*] Done\n";
	return 0;
}
