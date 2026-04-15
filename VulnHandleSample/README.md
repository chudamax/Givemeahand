# VulnHandleSample

A **vulnerable-by-design** Windows application that leaks privileged handles into a lower-privilege child process. Bundled alongside [Givemeahand](../README.md) as the training / self-test target for the scanner.

Originally authored by [@bananabr](https://github.com/bananabr/VulnHandleSample); this copy contains modifications required to reproduce the leak on Windows 11 (26200) — see **Modifications** below.

## What it does

Run elevated (High IL / admin UAC context). No arguments.

1. Enables `SeIncreaseQuotaPrivilege`.
2. Opens inheritable handles to privileged resources:
   - `CreateFile("C:\Windows\System32\notepad.exe", GENERIC_READ)` with `bInheritHandle = TRUE`.
   - `OpenProcess(PROCESS_ALL_ACCESS, bInheritHandle=TRUE, self)` — a self-handle with full rights.
   - `OpenThread(THREAD_ALL_ACCESS, bInheritHandle=TRUE, self)` — ditto on the main thread.
3. Duplicates its own primary token and lowers the integrity level on the duplicate to **Medium**.
4. Spawns `cmd.exe` via `CreateProcessAsUserW`:
   - Token: the Medium-IL duplicate from step 3.
   - `bInheritHandles = TRUE` → the handles from step 2 propagate into the child.
   - Creation flags: `CREATE_SUSPENDED | CREATE_NO_WINDOW` → child exists solely to hold the leaked handles, no entry-point execution, no visible console.
   - `lpProcessAttributes` → a security descriptor with a **NULL DACL**, so any same-user process can open the child for `PROCESS_DUP_HANDLE`. (Without this, the child inherits the admin token's default DACL which only grants `BUILTIN\Administrators`, and a non-elevated UAC-split scanner gets `ERROR_ACCESS_DENIED`.)
5. Calls `SuspendThread` on its own main thread so it stays alive indefinitely, keeping the leaked handles valid.

At this point:

- `VulnHandleSample.exe` itself runs at High IL, main thread suspended.
- One Medium-IL `cmd.exe` child, also suspended, no console window, same user.
- The child's handle table contains inheritable handles whose targets live in the elevated parent.

Exit via Ctrl+C or Task Manager — that kills VulnHandleSample and its suspended cmd.exe child.

## Build

```
msbuild VulnHandleSample.vcxproj /p:Configuration=Release /p:Platform=x64
```

No dependencies.

## Modifications from the original

The upstream project used `CreateProcessWithTokenW` to spawn `notepad.exe`. This does not actually reproduce the leak on Windows 11:

1. **`CreateProcessWithTokenW` → `CreateProcessAsUserW`.** `CreateProcessWithTokenW` routes process creation through the secondary-logon service, which does not propagate the caller's inheritable handles. `CreateProcessAsUserW` honors `bInheritHandles=TRUE` directly.
2. **Own-token derivation instead of argv-based target PID.** `CreateProcessAsUserW` normally requires `SeAssignPrimaryTokenPrivilege`, which regular admin tokens do not hold (only SYSTEM / LOCAL SERVICE / NETWORK SERVICE do). MSDN carves out an exception when the new token is derived from the caller's own primary token — so we duplicate our own token and lower its integrity level to Medium, which sidesteps the privilege requirement.
3. **`notepad.exe` → `cmd.exe`.** On Windows 11, `C:\Windows\System32\notepad.exe` is a shim for the UWP packaged Notepad app, which runs in an AppContainer. AppContainer process objects deny `PROCESS_DUP_HANDLE` cross-process even from the same user at the same IL, blocking any scanner from accessing the leaked handles. A classic Win32 binary (`cmd.exe`) doesn't have that restriction.
4. **`CREATE_SUSPENDED | CREATE_NO_WINDOW`.** Keeps the spawned `cmd.exe` from actually running its entry point and suppresses the console window.
5. **NULL DACL `lpProcessAttributes`.** See point 4 in *What it does* — required so a non-elevated same-user scanner can `OpenProcess(PROCESS_DUP_HANDLE)` on the child.
6. **Removed the argv-based target user PID.** No longer needed with own-token derivation.

Together, these make the leak actually observable on Windows 11 26200 + a UAC-split admin session.

## Usage

From an elevated cmd / PowerShell (UAC prompt required):

```
C:\path\to\VulnHandleSample\x64\Release\VulnHandleSample.exe
```

Output:

```
[+] File handle: 00000000000000E4
[+] Process handle: 0000000000000114
[+] Thread handle: 0000000000000118
[+] Spawned Medium-IL child PID: 36064
```

Note the child PID — a paired scanner (see Givemeahand) will report it as the holder of leaked High-IL handles.

## See also

- [Givemeahand](../README.md) — the sibling scanner / exploiter this sample is paired with.
- https://aptw.tf/2022/02/10/leaked-handle-hunting.html — the writeup explaining the primitive.
- [CVE-2025-6759](https://www.rapid7.com/blog/post/cve-2025-6759-citrix-virtual-apps-and-desktops-fixed/) — a real-world instance of the same pattern.
