# Givemeahand

A scanner and one-shot exploiter for the **leaked privileged handle** local-privilege-escalation primitive on Windows.

Based on:
- https://aptw.tf/2022/02/10/leaked-handle-hunting.html
- http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/

## What it does

Walks the system handle table, finds low-privilege processes holding inheritable handles that target higher-privilege objects, and reports exactly which primitive can weaponize each one. With the exploit build, turns the finding into a High-IL / SYSTEM process on the first hit.

Detects handles of three object types — **Process**, **Thread**, **Token** — with access masks that map to a concrete LPE primitive:

| Object  | Access mask                                          | Primitive                                                  |
|---------|------------------------------------------------------|------------------------------------------------------------|
| Process | `PROCESS_ALL_ACCESS`                                 | Parent-process spoofing (`CreatePrivProc`)                 |
| Process | `PROCESS_CREATE_PROCESS`                             | Parent-process spoofing (`CreatePrivProc`)                 |
| Process | `PROCESS_CREATE_THREAD \| PROCESS_VM_WRITE`          | DLL injection (`ExploitCreateThread`)                      |
| Process | `PROCESS_DUP_HANDLE` *(loose mode)*                  | Handle-table brute force (`ExploitDupHandle`)              |
| Thread  | `THREAD_ALL_ACCESS` / `THREAD_DIRECT_IMPERSONATION`  | `NtImpersonateThread` → primary token → `CreateProcessWithTokenW` |
| Token   | `TOKEN_DUPLICATE` / `TOKEN_ASSIGN_PRIMARY`           | Direct token theft (no process/thread handle needed)      |

## Why handles get leaked

Canonical pattern (e.g. [CVE-2025-6759](https://www.rapid7.com/blog/post/cve-2025-6759-citrix-virtual-apps-and-desktops-fixed/), Citrix `GfxMgr.exe` → `CtxGfx.exe`):

1. A privileged service (SYSTEM or elevated admin) opens a handle with `bInheritHandle = TRUE` — e.g. a self-handle, a service manager, etc.
2. The service spawns a **lower-privilege** child via `CreateProcessAsUserW(..., bInheritHandles=TRUE, ...)` — typically because it needs to run code as the interactive user.
3. The kernel propagates the inheritable high-privilege handles into the low-privilege child. The child now owns a handle whose access mask was computed against the parent's privileges.
4. A local attacker running as that low-privilege user can `DuplicateHandle` the leaked handle out of the child and use it as if they were the original privileged caller.

## Detection pipeline

1. **Snapshot the system handle table** via `NtQuerySystemInformation(SystemHandleInformation)` with a grow-loop on `STATUS_INFO_LENGTH_MISMATCH`.

2. **Resolve `ObjectTypeNumber` → type name at runtime.** The numeric indices for Process/Thread/Token drift across Windows builds (on Win11 26200: Process=0x8, Thread=0x9, Token=0x5 — different from the Win7-era constants that older tools hardcode). Givemeahand pre-opens known-type handles on itself, then calls `NtQueryObject(ObjectTypeInformation)` to build a live `ObjectTypeNumber → name` map for dispatch.

3. **Build a tid→pid map** (`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`) so leaked thread handles can be resolved back to their owning process for integrity lookup.

4. **Dispatch per entry** and clone each candidate handle with `DuplicateHandle(..., DUPLICATE_SAME_ACCESS)`.

5. **Apply the strict exploitability filter** (default):
   - Access mask must map to a concrete primitive from the table above.
   - Target must be a live process (`GetProcessId` returns a non-zero PID **and** `CreateToolhelp32Snapshot` can resolve its name — zombies kept alive only by handle references are filtered out).
   - Target must not be the handle's holder (no self-references).
   - Target integrity level must be strictly higher than the scanner's own IL **and** at least `SECURITY_MANDATORY_HIGH_RID`.
   - `ACCESS_DENIED` on the IL query no longer auto-passes. This heuristic used to accept e.g. `TOKEN_IMPERSONATE`-only handles as "probably high IL" and produced hundreds of false positives from normal sandbox IPC.

6. **Report, or (with `EXPLOIT_ENABLED`) fire the matching primitive** and return on first success.

## Output

```
[*] Scanner IL: 0x2000

[!] HOLDER: cmd.exe (36064)
    |_ Handle value:  0x60
    |_ Object type:   0x8
    |_ Access granted: 0x1fffff
    |_ TARGET: VulnHandleSample.exe (40676) IL=0x3000
    |_ Primitive:     ALL_ACCESS -> parent-spoof (CreatePrivProc)

[!] HOLDER: cmd.exe (36064)
    |_ Handle value:  0xb8
    |_ Object type:   0x9
    |_ Access granted: 0x1fffff
    |_ TARGET: VulnHandleSample.exe (40676) IL=0x3000
    |_ Primitive:     THREAD_ALL_ACCESS -> thread impersonation (NtImpersonateThread)

[!] Found 2 vulnerable handles
```

Each finding names the **holder** (the process where the handle lives), the **target** (which the handle points at), the **access mask**, and the **primitive** to weaponize it.

## CLI

```
Givemeahand [options]

Detection:
  --loose              Include weaker rights (DUP_HANDLE, SET_CONTEXT,
                       TOKEN_IMPERSONATE) — noisier but covers CVE-2025-6759-style
                       DUP_HANDLE-only leaks.
  --all                Disable all filtering, show every Process/Thread/Token
                       handle in the system. Forensics only.

Exploit (requires EXPLOIT_ENABLED build):
  --cmd "<cmdline>"    Command line to spawn via a process-based primitive.
  --dll "<path>"       DLL to inject via PROCESS_CREATE_THREAD primitive.
  --primitive <kind>   Restrict exploit to a single primitive:
                         parent  — CreatePrivProc (needs CREATE_PROCESS)
                         dup     — ExploitDupHandle (needs DUP_HANDLE)
                         thread  — ExploitCreateThread (needs CREATE_THREAD+VM)
                         imper   — ExploitThreadImpersonation (thread handle)

Diagnostics:
  --pid <N>            Dump every handle owned by PID N — types, access masks.
                       Useful for verifying what a process actually holds before
                       triaging a finding.
  --trace-pid <N>      For every handle owned by PID N that would enter a
                       dispatch branch, print the clone result, IL query
                       result, and filter decision. Distinguishes "couldn't
                       clone", "target dead", "target too low IL" when the
                       filter silently drops a hit.

  -h | --help          Usage.
```

## Build

Three configurations in `Givemeahand.vcxproj`:

| Config     | Output                            | Defines            | Notes                                   |
|------------|-----------------------------------|--------------------|-----------------------------------------|
| `Release`  | `x64\Release\Givemeahand.exe`     | (none)             | Detection only. Dynamic CRT.            |
| `Detect`   | `x64\Detect\Givemeahand.exe`      | (none)             | Detection only. **Static CRT** — drop-in portable binary. |
| `Exploit`  | `x64\Exploit\Givemeahand.exe`     | `EXPLOIT_ENABLED`  | Detection + exploit primitives. Static CRT. |

Build from a Developer Command Prompt:

```
msbuild Givemeahand.vcxproj /p:Configuration=Detect  /p:Platform=x64
msbuild Givemeahand.vcxproj /p:Configuration=Exploit /p:Platform=x64
```

No third-party dependencies.

## Applicability

Works against any real-world instance of the leaked-handle pattern. For CVE-2025-6759 (Citrix VAD, unpatched): run as the session user, Givemeahand reports `CtxGfx.exe` holding a SYSTEM process handle. With the Exploit build and `--primitive parent --cmd "..."`, `CreatePrivProc` spawns the command parented to `GfxMgr.exe`, inheriting SYSTEM's primary token.

**Preconditions on the target:**
- Scanner must run **as the same user** that owns the vulnerable holder process. `OpenProcess(PROCESS_DUP_HANDLE, holder)` is required to clone the leaked handle out of the holder.
- The holder must not be an AppContainer / packaged UWP app (their process objects deny `PROCESS_DUP_HANDLE` cross-process even at the same IL).
- The holder's process SD must not exclude your token. A UAC-split admin token where the only grantee is `BUILTIN\Administrators` (Deny-only in the filtered token) will be refused — run as a standard user or ensure the holder's SD grants your user SID directly.

## Known limitations

- **Object types covered:** Process, Thread, Token. Leaked Section / File / Registry Key / ALPC Port handles are not inspected.
- **Handle-value truncation:** `SYSTEM_HANDLE_TABLE_ENTRY_INFO.UniqueProcessId` is `USHORT`. PIDs > 65535 get truncated. Use `SystemExtendedHandleInformation` (class 0x40) for a 64-bit-clean enumeration — this tool doesn't yet.
- **Exploit-mode first-match-wins:** one successful primitive returns from `main`. Run in detection mode to enumerate every leak on a box.
- **`CreateProcessAsUserW` vs. `CreateProcessWithTokenW`:** only the former propagates `bInheritHandles=TRUE`. `CreateProcessWithTokenW` routes through the secondary-logon service and does not.
- **Snapshot-based:** short-lived holders can be missed between the enum and the clone step.

## Credits

- https://aptw.tf/2022/02/10/leaked-handle-hunting.html — the technique writeup this tool is based on.
- http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/ — earlier exploration of the primitives.
- https://github.com/bananabr/VulnHandleSample — paired vulnerable target (a modified version is shipped alongside this repo with fixes for Win11 behavior: `CreateProcessAsUserW` instead of `CreateProcessWithTokenW`, own-token derivation to avoid `SeAssignPrimaryTokenPrivilege`, classic Win32 `cmd.exe` target instead of UWP notepad, NULL-DACL process attributes).
