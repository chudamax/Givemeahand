# Givemeahand — Leaked Handle Detection & Exploitation

A Windows PoC scanner/exploiter for the **leaked privileged handle** local-privilege-escalation primitive, as described in:
- https://aptw.tf/2022/02/10/leaked-handle-hunting.html
- http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/

- `Givemeahand.cpp` / `utils.cpp` — the scanner and exploit primitives.
- `VulnHandleSample/` — a vulnerable-by-design target bundled in-tree for training and self-test. Demonstrates the bug givemeahand is designed to find.

---

## 1. The vulnerability class

When a high-privilege process (e.g. SYSTEM or High-IL admin) opens a kernel object with `bInheritHandle = TRUE` and later spawns a child with `CreateProcessAsUserW(..., bInheritHandles=TRUE, ...)`, the child **inherits those handles with the same access mask the parent held**, regardless of the child's own privilege level. The kernel enforces access at *open* time, not at *use* time — so once a low-IL process owns a `PROCESS_ALL_ACCESS` handle to a SYSTEM process, it can act on that handle as if it were SYSTEM itself.

Real-world instances look like [CVE-2025-6759](https://www.rapid7.com/blog/post/cve-2025-6759-citrix-virtual-apps-and-desktops-fixed/) (Citrix `GfxMgr.exe` → `CtxGfx.exe`), where a service running as SYSTEM leaks a `PROCESS_ALL_ACCESS` handle to its low-privilege user-session child.

### Exploit primitives, by leaked access right

| Leaked right (on process handle)        | Turns into                                                                 |
|-----------------------------------------|----------------------------------------------------------------------------|
| `PROCESS_CREATE_PROCESS` / `_ALL_ACCESS`| Spawn arbitrary command via parent-process spoofing (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) |
| `PROCESS_DUP_HANDLE`                    | Brute-force target's handle table, steal a different privileged handle, pivot |
| `PROCESS_CREATE_THREAD` + `VM_OPERATION`/`VM_WRITE` | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread(LoadLibraryW)` DLL injection |
| `THREAD_DIRECT_IMPERSONATION` / `THREAD_ALL_ACCESS` | `NtImpersonateThread` → primary token → `CreateProcessWithTokenW`     |
| `TOKEN_IMPERSONATE` / `_DUPLICATE` / `_ASSIGN_PRIMARY` on a high-IL token | Direct token theft — no process/thread handle needed |

---

## 2. `VulnHandleSample` — the target

A minimal, vulnerable-by-design app. Must run elevated (High IL / admin UAC context).

### What it does on each run
1. Enables `SeIncreaseQuotaPrivilege`.
2. Opens inheritable handles to privileged resources:
   - `CreateFile("C:\Windows\System32\notepad.exe", GENERIC_READ, ..., bInheritHandle=TRUE)`
   - `OpenProcess(PROCESS_ALL_ACCESS, bInheritHandle=TRUE, self)` — a self-handle with full rights
   - `OpenThread(THREAD_ALL_ACCESS, bInheritHandle=TRUE, self)` — ditto on the main thread
3. Duplicates its own primary token and lowers the integrity level to **Medium** on the duplicate. (Deriving the child token from the caller's own token avoids the `SeAssignPrimaryTokenPrivilege` requirement — admin doesn't hold that privilege by default; only SYSTEM/services do.)
4. Calls `CreateProcessAsUserW(hMediumToken, "cmd.exe", ..., bInheritHandles=TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, lpProcessAttributes=<NULL DACL>)`:
   - `bInheritHandles=TRUE` is what propagates the high-privilege handles into the child.
   - `CREATE_SUSPENDED` means `cmd.exe`'s entry point never runs — the process exists solely to hold the leaked handles.
   - `CREATE_NO_WINDOW` hides the console.
   - A **NULL-DACL** security descriptor on `lpProcessAttributes` makes the child process's kernel object world-accessible, so any same-user Medium-IL scanner can open it for `PROCESS_DUP_HANDLE`. Without this, the default DACL inherited from the admin token grants only `BUILTIN\Administrators`, and a UAC-split non-elevated admin token has that group as deny-only.
5. Calls `SuspendThread(hThread)` on its own main thread so the parent stays alive indefinitely, keeping the leaked handles valid for the scanner to find.

### What you should observe
- One elevated `VulnHandleSample.exe` process (High IL), main thread suspended.
- One Medium-IL `cmd.exe` child, also suspended, belonging to the same user, with no console window.
- The child's handle table contains three inheritable handles whose targets live in the elevated parent: a File, a Process handle with `PROCESS_ALL_ACCESS`, a Thread handle with `THREAD_ALL_ACCESS`.

### How to run
From an **elevated** cmd/PowerShell (UAC prompt required):

```
VulnHandleSample\x64\Release\VulnHandleSample.exe
```

No arguments. Prints the child PID on the `[+] Spawned Medium-IL child PID: <N>` line.

Ctrl+C or close the window to clean up — that kills VulnHandleSample and its suspended cmd.exe child.

---

## 3. `givemeahand` — the scanner/exploiter

A single-binary tool that enumerates the system-wide handle table, filters for dangerous handles held by processes with lower integrity than their targets, and (if built with `EXPLOIT_ENABLED`) weaponizes them.

### Build configurations

Three configurations are defined in `Givemeahand.vcxproj`:

| Config    | Output                         | `EXPLOIT_ENABLED` | CRT         | Purpose                                   |
|-----------|--------------------------------|-------------------|-------------|-------------------------------------------|
| `Release` | `x64\Release\Givemeahand.exe`  | no                | Dynamic MD  | Default dev build                         |
| `Detect`  | `x64\Detect\Givemeahand.exe`   | no                | Static MT   | Portable detection-only binary            |
| `Exploit` | `x64\Exploit\Givemeahand.exe`  | **yes**           | Static MT   | Detection + weaponized exploit primitives |

Pick the config at build time — do not try to hack preprocessor defines onto `Release` (MSBuild's `DefineConstants` is C#-only; for C++ set `AdditionalPreprocessorDefinitions` or use the pre-baked `Exploit` config):

```
msbuild Givemeahand.vcxproj /p:Configuration=Detect  /p:Platform=x64
msbuild Givemeahand.vcxproj /p:Configuration=Exploit /p:Platform=x64
```

### Detection pipeline

1. **Snapshot the system handle table**
   Calls `NtQuerySystemInformation(SystemHandleInformation)` in a grow-loop until the buffer fits (`STATUS_INFO_LENGTH_MISMATCH` = 0xC0000004 triggers a realloc+retry). Each entry is a `SYSTEM_HANDLE_TABLE_ENTRY_INFO`: owning PID, handle value, `ObjectTypeNumber`, granted access mask, object pointer.

2. **Resolve `ObjectTypeNumber` → type name at runtime**
   The `ObjectTypeNumber` index for `Process` / `Thread` / `Token` drifts across Windows builds (on Win11 26200: Process=0x8, Thread=0x9, Token=0x5, File=0x2a — different from the old Win7-era hardcoded `7/8/5/0x37`). The tool resolves them dynamically:
   - Pre-opens its own process / thread / primary token handles *before* the snapshot.
   - After the snapshot, walks its own-process entries, calls `NtQueryObject(ObjectTypeInformation)` on each to read the type name, and builds an `ObjectTypeNumber → name` map.
   - Picks the numbers for `"Process"`, `"Thread"`, `"Token"` from that map and uses them for dispatch instead of hardcoded constants.

3. **Build a tid→pid map**
   Via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` so a leaked thread handle can be resolved back to its owning process for integrity-level lookup.

4. **Dispatch per entry**

   For every handle in the snapshot, branch on resolved type:

   - **Process / Thread / Token** — apply the exploitability filter (see below), clone via `DuplicateHandle(..., DUPLICATE_SAME_ACCESS)`, and IL-filter the target.

### Exploitability filter (default = STRICT)

The default filter only reports handles where the access mask maps to a concrete, practically-exploitable LPE primitive and the target is a real live process at a strictly higher integrity level than the scanner itself.

| Branch  | Strict match                                                                                      | Primitive                                           |
|---------|---------------------------------------------------------------------------------------------------|-----------------------------------------------------|
| Process | `PROCESS_ALL_ACCESS`                                                                              | parent-spoof → `CreatePrivProc`                     |
| Process | `PROCESS_CREATE_PROCESS`                                                                          | parent-spoof → `CreatePrivProc`                     |
| Process | `PROCESS_CREATE_THREAD` **and** `PROCESS_VM_WRITE`                                                 | DLL injection → `ExploitCreateThread`               |
| Thread  | `THREAD_ALL_ACCESS`                                                                                | impersonation → `ExploitThreadImpersonation`        |
| Thread  | `THREAD_DIRECT_IMPERSONATION`                                                                      | impersonation → `ExploitThreadImpersonation`        |
| Token   | `TOKEN_DUPLICATE`                                                                                  | direct token theft                                  |
| Token   | `TOKEN_ASSIGN_PRIMARY`                                                                             | direct token theft                                  |

Plus these post-match gates for process/thread handles:

- `GetProcessId(cloned)` returns non-zero **and** `GetProcName(target)` resolves — filters out zombie processes kept alive only by handle references, which can't be parent-spoofed.
- Target PID != holder PID — self-handles are not privesc primitives.
- Target IL > scanner's own IL **and** target IL ≥ `SECURITY_MANDATORY_HIGH_RID`.
- `ACCESS_DENIED` on the IL query no longer auto-passes (that heuristic used to wave through hundreds of `TOKEN_IMPERSONATE`-only hits from sandbox IPC — they are almost always the scanner failing to walk a restricted thread-impersonation token, not a privileged target).

**Bare `PROCESS_DUP_HANDLE` is excluded from the strict set.** In theory it's a real primitive (brute-force the holder's handle table), but on modern Windows it overwhelmingly fires on sandbox broker IPC where the DUP_HANDLE target isn't privileged. Use `--loose` to include it; that's the mode to use for CVE-2025-6759-style triage.

### Filter flags

| Flag        | Behavior |
|-------------|----------|
| (default)   | Strict: exploitable-only, live targets, real privesc. |
| `--loose`   | Include `PROCESS_DUP_HANDLE`, `PROCESS_VM_OPERATION`, `THREAD_SET_CONTEXT`, `THREAD_SUSPEND_RESUME`, `TOKEN_IMPERSONATE`. Noisier but catches `DUP_HANDLE`-only leaks. |
| `--all`     | Disable all filtering — every Process/Thread/Token handle system-wide. Forensics only. |

5. **Clone the handle**
   `CloneHandle` in `utils.cpp` is the workhorse: `OpenProcess(PROCESS_DUP_HANDLE, owner_pid)` + `DuplicateHandle(..., DUPLICATE_SAME_ACCESS)`. This pulls the handle out of the owning process's handle table and into the scanner's own, carrying the original access mask.

   If `OpenProcess` fails with `ERROR_ACCESS_DENIED` (5), the scanner can't touch that handle — typical causes: scanner runs as a different user, scanner hits a split-token admin situation, the target is AppContainer/UWP, or the target's SD denies cross-process duplication.

6. **Integrity-level filter**
   After cloning, the tool checks the *target*'s integrity level (not the owning process's):
   - For process handles: `OpenProcessToken` on the cloned handle, read `TokenIntegrityLevel`.
   - For thread handles: resolve tid → pid → query IL via `PROCESS_QUERY_LIMITED_INFORMATION`.
   - For token handles: query IL directly from the token.

   A handle is reported iff `targetIL >= SECURITY_MANDATORY_HIGH_RID` (0x3000 = 12288), **or** `GetTargetIntegrityLevel` returned `ERROR_ACCESS_DENIED` (interpreted as "the target is higher than us, worth trying"). Handles where the target is at or below the scanner's own IL are ignored — those aren't privilege escalations.

7. **Print or exploit**
   Detection mode prints `[*] Process: <name> (pid) | handle | object | type | access | IL`. Exploit mode additionally fires the matching primitive (see table below) and exits on first success.

### Exploit primitives (in `utils.cpp`, `EXPLOIT_ENABLED`)

| Primitive function         | Required leaked access              | Technique |
|----------------------------|-------------------------------------|-----------|
| `CreatePrivProc`           | `PROCESS_CREATE_PROCESS`            | `InitializeProcThreadAttributeList` + `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` + `CreateProcess(EXTENDED_STARTUPINFO_PRESENT)`. The new process's parent is the privileged target, so the child inherits its token. Used with `--cmd`. |
| `ExploitDupHandle`         | `PROCESS_DUP_HANDLE`                | Brute-force handle values `0x4..0x1000` step 4 in the target, `DuplicateHandle(..., DUPLICATE_SAME_ACCESS)` each one, filter for process handles at High+ IL, pivot into `CreatePrivProc`. Used with `--cmd`. |
| `ExploitCreateThread`      | `PROCESS_CREATE_THREAD` + VM rights | `VirtualAllocEx` + `WriteProcessMemory(dllPath)` + `CreateRemoteThread(LoadLibraryW)`. `LoadLibraryW`'s address is resolved locally — per-session kernel32 ASLR is consistent across processes. Used with `--dll`. |
| `ExploitThreadImpersonation` | `THREAD_DIRECT_IMPERSONATION` / `THREAD_ALL_ACCESS` | `NtImpersonateThread` to copy the target thread's token onto the scanner's calling thread → `OpenThreadToken` → `DuplicateTokenEx` to primary → `CreateProcessWithTokenW`. Must stay impersonating across the `CreateProcessWithTokenW` call so `SeImpersonatePrivilege` is present. Used with `--cmd`. |

**First-match-wins:** each branch `return`s from `wmain` on success, so one run spawns at most one privileged process.

### CLI

```
Givemeahand [options]

Detection:
  --loose                  Include weaker rights (DUP_HANDLE, SET_CONTEXT, IMPERSONATE)
  --all                    Disable all filtering, show every handle

Exploit (EXPLOIT_ENABLED build):
  --cmd "<cmdline>"        Command line for process-based primitives
  --dll "<path>"           DLL to inject via CREATE_THREAD primitive
  --primitive <parent|dup|thread|imper>
                           Restrict exploit to a single primitive path

Diagnostics:
  --pid <N>                Dump every handle owned by PID N
  --trace-pid <N>          Trace clone/IL checks for PID N

  -h | --help              Usage
```

### Diagnostic flags

Added while debugging and left in for future drift issues:

- **Histogram** — on startup, prints counts of every `ObjectTypeNumber` seen system-wide, annotated with the resolved type name from `NtQueryObject`. Use this to verify the Process/Thread/Token indices were resolved, or to spot a new Windows build where the table shifted again.
- **`--pid N`** — dumps every `{handle, type, access}` triple owned by PID `N`, regardless of whether it's "interesting." Use this to verify a specific process really does hold the handles you expect before troubleshooting the filter.
- **`--trace-pid N`** — for every handle owned by PID `N` that would enter the process/thread/token branches, print the `OpenProcess` result, `DuplicateHandle` result, and resolved target IL. Distinguishes "handle doesn't exist," "can't open owner," "can't duplicate," and "target IL too low" when the filter silently drops something.

---

## 4. End-to-end demo

Self-contained reproduction using the paired tools.

1. **Build both** (from a Developer Command Prompt):
   ```
   msbuild Givemeahand.vcxproj               /p:Configuration=Detect  /p:Platform=x64
   msbuild VulnHandleSample\VulnHandleSample.vcxproj /p:Configuration=Release /p:Platform=x64
   ```

2. **Run the target elevated** (UAC prompt):
   ```
   VulnHandleSample\x64\Release\VulnHandleSample.exe
   ```
   Note the printed `[+] Spawned Medium-IL child PID: <N>`.

3. **Run the scanner unelevated** as the same user:
   ```
   x64\Detect\Givemeahand.exe --trace-pid <N>
   ```

   Expected output:
   ```
   [*] Scanner IL: 0x2000
   [*] Resolved indices: Process=0x8 Thread=0x9 Token=0x5

   [!] HOLDER: cmd.exe (<N>)
       |_ Handle value:  0x60
       |_ Object type:   0x8
       |_ Access granted: 0x1fffff
       |_ TARGET: VulnHandleSample.exe (<parent>) IL=0x3000
       |_ Primitive:     ALL_ACCESS -> parent-spoof (CreatePrivProc)

   [!] HOLDER: cmd.exe (<N>)
       |_ Handle value:  0xb8
       |_ Object type:   0x9
       |_ Access granted: 0x1fffff
       |_ TARGET: VulnHandleSample.exe (<parent>) IL=0x3000
       |_ Primitive:     THREAD_ALL_ACCESS -> thread impersonation

   [!] Found 2 vulnerable handles
   ```

4. **Exploit** (with the `Exploit` config, which defines `EXPLOIT_ENABLED`):
   ```
   x64\Exploit\Givemeahand.exe --primitive parent --cmd "cmd.exe /c whoami /all > C:\out.txt"
   ```
   Clones the `PROCESS_ALL_ACCESS` handle from `cmd.exe` → VulnHandleSample, uses it as `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, spawns a new `cmd.exe` parented to the elevated VulnHandleSample. The new process inherits the parent's primary token (High IL / admin), runs `whoami /all`, writes to `C:\out.txt`. Verify it shows `Mandatory Label\High Mandatory Level` and `BUILTIN\Administrators` enabled (not deny-only).

5. **Cleanup**: stop `VulnHandleSample.exe` in the elevated shell — its suspended `cmd.exe` child dies with it.

---

## 5. Applicability to real CVEs

The scanner works against any real-world instance of the same primitive, e.g. [CVE-2025-6759](https://www.rapid7.com/blog/post/cve-2025-6759-citrix-virtual-apps-and-desktops-fixed/) (unpatched Citrix VAD): `GfxMgr.exe` (SYSTEM) leaks a `PROCESS_ALL_ACCESS` handle into the user-session `CtxGfx.exe`. Run Givemeahand as the session user, it will report `CtxGfx.exe` holding a SYSTEM-IL process handle. With `EXPLOIT_ENABLED --cmd ...`, the `CreatePrivProc` path (parent-process spoofing) turns that into a SYSTEM-context command.

Preconditions for real-world detection:
- Scanner must run **as the same user** that owns the vulnerable recipient process — otherwise `OpenProcess(PROCESS_DUP_HANDLE)` on the recipient fails.
- Recipient must be alive when you scan.
- Recipient must not be AppContainer/UWP (UWP kernel objects deny cross-process `PROCESS_DUP_HANDLE` even from the same user).
- Recipient's process SD must not explicitly deny PROCESS_DUP_HANDLE to your token. A split-token admin (non-elevated) where the only grantee is `BUILTIN\Administrators` will be denied.

---

## 6. Demonstrated end-to-end LPE

A clean run of the full chain, captured during development:

```
Scanner IL: 0x2000 (Medium, UAC-split admin)

Finding:
  HOLDER:    cmd.exe (36064)   — Medium IL, spawned by VulnHandleSample
  Handle:    0x60   type=0x8   access=0x1fffff (PROCESS_ALL_ACCESS)
  TARGET:    VulnHandleSample.exe (40676)   IL=0x3000 (High)
  Primitive: parent-spoof (CreatePrivProc)

Exploit:
  CloneHandle(36064, 0x60) → new handle in Givemeahand
  CreateProcess(..., lpStartupInfo.lpAttributeList = {
      PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = <cloned handle>
  }, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW)
  → new cmd.exe (PID 50860), parented to VulnHandleSample,
    inherits VulnHandleSample's primary token.

whoami /all inside the spawned process:
  Integrity Level          : Mandatory Label\High Mandatory Level (S-1-16-12288)
  BUILTIN\Administrators   : Enabled (not deny-only)
  SeDebugPrivilege         : Enabled
  SeImpersonatePrivilege   : Enabled
  SeLoadDriverPrivilege    : present
  SeBackup/RestorePrivilege: present
```

Starting state: Medium-IL UAC-split admin shell. Ending state: a process at High IL with full admin SIDs enabled and debug privilege. No UAC prompt, no password prompt.

## 7. Known limitations

- **Object types covered:** Process, Thread, Token only. A leaked Section, File, Registry Key, ALPC Port, etc. would not be detected.
- **Handle-value truncation:** `SYSTEM_HANDLE_TABLE_ENTRY_INFO.UniqueProcessId` is `USHORT` — PIDs above 65535 are truncated. Modern Windows can assign PIDs in that range on long-running sessions. Use `SystemExtendedHandleInformation` (class 0x40) for a 64-bit clean version; this tool doesn't yet.
- **Type-index drift:** `OB_TYPE_INDEX_*` constants in `support.h` are stale for Win11 26200 (hardcoded to the Win7-era values 5/7/8/0x37). The scanner ignores them and resolves at runtime — but the constants are still in the header, and anything else that imports them will be wrong. Consider deleting them.
- **`CreateProcessAsUserW` vs. `CreateProcessWithTokenW`:** only the former honors `bInheritHandles=TRUE`. `CreateProcessWithTokenW` routes through the secondary-logon service and does **not** propagate inheritable handles, so it can't be used to construct a leak.
- **Exploit-mode first-match-wins:** one successful primitive terminates the scan. If you need to enumerate *all* leaks on a box, run in detection mode.
- **Detection is best-effort:** the scan is a single snapshot. Short-lived recipient processes can be missed.

---

## 8. Files

```
Givemeahand.cpp                         scanner main + dispatch + diagnostics
Givemeahand.h                           scanner header
utils.cpp                               CloneHandle, IL lookups, exploit primitives
utils.h                                 exports
support.h                               NT structs + (stale) OB_TYPE_INDEX_* constants
Givemeahand.vcxproj                     3 configs: Release / Detect / Exploit
README.md                               GitHub-facing overview
DOCS.md                                 this file — detailed docs
VulnHandleSample/                       bundled vulnerable target for self-test
  VulnHandleSample.cpp                  vulnerable target (main)
  VulnHandleSample.vcxproj              build config
  README.md                             target docs + fork modification notes
```
