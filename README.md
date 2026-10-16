---
tags: [hpcc4, windows, scripts]
updated: 2026-10-15
---

# HPCC4 scripts - what is here and how to use it

Everything is Windows PowerShell 5.1 (the `powershell.exe` already on Server 2022), plain ASCII, no installs.
**For the competition, print and read `RUNBOOK.md`**: commands in phase order, break-glass steps, what to do when something breaks.
This file is the map. `ARCHITECTURE.md` explains how the code is put together.

## What is here

| Script | Run it | What it does |
|---|---|---|
| `Start-Hardening.ps1` (+ `lib\`) | box, elevated | THE TOOL. Audits the box phase by phase (1 Recon, 2 Accounts, 3 Backup, 4 Firewall, 6 Hunt, 7 Defender, 8 Watchdog, 9 Routine) and fixes rows one at a time: preview, your confirmation, journal, undo. A window by default, `-NoGui` for text. Starts READ-ONLY. Phase 6 also audits the places a program hides to start again (Run keys, WMI, IFEO ...) and most rows have their own Fix (delete ONE registry value, quarantine a file, remove a hosts line, a share or a WMI subscription); phase 7 diagnoses Defender and fixes exclusions and switched-off scanning |
| `Panic.ps1` | box, elevated (short enough to type on the NEIGH Console) | Break glass: puts the saved firewall policy back, switches network adapters on, allows RDP, enables `jmoney`, starts Jenkins. It is also what the dead-man task runs |
| `Watchdog.ps1` | box, elevated (the tool installs it as a SYSTEM task: phase 8) | OPTIONAL. Once a minute it checks Remote Desktop, `jmoney`, Jenkins and the two firewall allow rules and repairs them with the steps of `Panic.ps1`; it also writes `alerts.log` (new accounts, tasks and services, cleared logs, failed-logon bursts, changed Jenkins jobs). Never run on real Windows: lab-test it first, and leave it uninstalled if you cannot explain it |
| `Verify-Hardening.ps1` (+ `VerifyFacts.ps1`, `VerifyJudge*.ps1`) | box, elevated | Read-only: did the hardening follow the plan, and is scoring still safe? Written separately from the tool on purpose: two implementations, so one bug cannot fool both |
| `RUNBOOK.md` | paper | The manual for the day, including "By hand" blocks for when the tool will not run |
| `Lab\Reset-LabInsecure.ps1` | lab VM only | Re-arms the practice box with RANDOM problems and an encrypted answer key |
| `Verify-Hardening.ps1 -Lab` | lab VM only | Same check, plus grades you against the answer key (FIXED / PARTIAL / MISSED / UNKNOWN) |
| `Tests\Run-AllTests.ps1` | anywhere | Runs all logic tests against pretend boxes (never touches the real one) |

`Lab\` and `Tests\` stay on the laptop. RUNBOOK.md section 1.1 lists exactly what goes into the bundle for the box.

## Quick start (on the box, elevated PowerShell)

```
cd C:\hp
powershell -ep bypass .\Start-Hardening.ps1                    the window (read-only until you tick "Allow changes")
powershell -ep bypass .\Start-Hardening.ps1 -NoGui             print the audit and stop
powershell -ep bypass .\Start-Hardening.ps1 -NoGui -Apply      text menu: same checks, asks before every change
powershell -ep bypass .\Panic.ps1                              break glass
```

## How to read the code (in this order)

1. `lib\Core.ps1` - the plan as constants, journal, `Invoke-Change` (the ONLY function that changes the box), passwords.
2. `lib\Collect.ps1` - reads the box (read-only). 3. `lib\Judge*.ps1` - turn what was read into rows; no Windows calls.
4. One `lib\Act-*.ps1` (Accounts, Backup, Firewall, Hunt, Persist, Watchdog) - each function BUILDS one change; it does not run it.
5. `lib\Runner.ps1` - audit, pick a row, build the action, `Invoke-Change`, audit again. The text menu (`Console.ps1`) and the window (`Gui.ps1`) are thin layers on top.
6. `Panic.ps1`, then `lib\DeadMan.ps1`, then `Watchdog.ps1` if you plan to use it.

The check scripts follow the same idea: `ScoreLib.ps1` = one small `Test-*` function per check, used by `Verify-Hardening.ps1`. `VerifyFacts.ps1` = reads Windows.
`VerifyJudge*.ps1` = decides PASS/FAIL from those facts (no Windows calls). `Verify-Hardening.ps1` = just calls them in order.

## Reading the output

`PASS` works / plan satisfied. `FAIL` broken or a plan decision is violated. `WARN` look at it. `INFO` a fact. `SKIP` not tested
(it says why). Exit code: 0 = all PASS, 1 = at least one FAIL, 2 = no FAIL but some WARN/SKIP.
In the tool: red BAD, yellow WARN, gray INFO, green OK; `[fix]` means the tool can fix the row.

## Lab flow

1. Revert the `clean-lab` snapshot (best), then on the VM, elevated:
   `powershell -ep bypass .\Lab\Reset-LabInsecure.ps1 -IAmInTheLab` (type LAB, choose a passphrase; `-Intensity Hard`, `-Seed 4242` to replay).
   It asks before deleting leftover accounts; `-KeepUsers name1,name2` protects names (for example a referee's login).
2. Check that RDP and Jenkins work by hand (mstsc, browser) before you start.
3. Harden with the tool (`Start-Hardening.ps1`) or by hand from RUNBOOK.md. Time phases 1 and 2.
4. On the box: `.\Verify-Hardening.ps1 -NewAdmin <your-new-admin> -AskPassword -BlackboxIp <ip> -Lab`
   Add `-WatchMinutes 12` to see which planted timers still fire. Then check RDP and Jenkins by hand again.

FreeRDP (for the real RDP login line): official releases are source code only. On the laptop use WSL/Linux
(`sudo apt install freerdp3-x11`, then run Score-Check under PowerShell 7 there (optional extra, not in the bundle)) or a third-party Windows build
(`-FreeRdpPath C:\tools\wfreerdp.exe`). Without it that line says SKIP and prints the one command to run elsewhere.

## First run on the real lab VM - things only Windows can prove (I could not test these)

Do these in order. If a line says `this section crashed: ...` (the check scripts) or the tool prints a red error, keep the message:
it is a Windows-only call behaving differently from what I expected. In the tool a broken collector shows up as a row
"Could not read: ..." and never stops the rest of the audit.

1. `powershell -ep bypass .\Tests\Run-AllTests.ps1` ON THE VM (real Windows PowerShell 5.1). Every file should say `ok`
   (`Test-BackupTransfer` and `Test-Gui` show `0 passed`: they need Linux). A failure here is a 5.1 difference my Linux PowerShell 7 could not show.
2. `powershell -ep bypass .\Start-Hardening.ps1 -GuiSelfTest` must print OK. If it does not, the text menu (`-NoGui -Apply`) is the same tool.
3. `Start-Hardening.ps1 -NoGui` on the freshly reset lab (read-only). Do the rows describe the box correctly? Check: Jenkins service and home found,
   the account list, the firewall rule counts, "Team network", "Internet", the Defender rows. (The lab has no log collector: that WARN is expected.)
4. Open the window. Is the text readable at your screen size? Tick "Allow changes", Re-audit, click rows, use Fix selected on a harmless one (Guest),
   then Undo last. Close the window with the X while the dead-man switch is armed: it must ask before closing.
5. Dead-man switch: Arm, wait for it to FIRE once (the firewall must come back by itself and the row must say FIRED), then Arm again and Keep changes.
   Check in Task Scheduler that the task `NetCacheRestore` appears while armed and is gone after Keep.
6. Phase 2 with a stopwatch, then check RDP by hand: new admin, second RDP session, Confirm, retire the old admins, rotate jmoney (NEIGH step included).
   Look at the real group memberships afterwards (`net localgroup Administrators`). Then `Start-Hardening.ps1 -Journal` and `-UndoLast`.
7. Phase 4: arm, allow rules, profiles, disable the others, outbound deny. Check RDP and Jenkins after EVERY step. Look at `Get-NetFirewallRule -Group` / the Core Networking rules: they must still be enabled.
8. `Panic.ps1` after breaking things on purpose: disable jmoney, stop the Jenkins service, block 3389 in the firewall. Each one must come back.
9. Backup: take an as-found backup (needs .NET 4.6.1 or newer: the Recon row "PowerShell and .NET" says), make the key, look at its file permissions
   (`icacls C:\ProgramData\NetCacheSvc\ssh\id_backup` must list only SYSTEM and Administrators), then send to a Linux VM set up like RUNBOOK.md 5.1
   (this is the first time the in-box OpenSSH 8.1 client talks to it), verify the hash and open the archive ON that VM.
10. Phase 6 and 7 on the freshly reset lab (`-NoGui`): read the rows `Persistence audit` and `Could not check: ...`. The persistence and Defender readers (registry, WMI, SMB, BITS, Get-MpComputerStatus,
    Authenticode on the accessibility programs) were only ever run against the pretend box. A `Could not check` row means a reader broke on real Windows: keep its message. Do the planted items of the lab show up?
    Also make sure Defender's own services and Jenkins do NOT appear as a fixable row.
11. The phase 6 and 7 FIXES, one planted item of each kind (the lab plants Run keys, startup files, IFEO, WMI, hosts lines, shares, tasks under `\Microsoft\` and Defender exclusions):
    press Fix on it, read the question, confirm, Re-audit (the row must be gone), then Undo and Re-audit (the row must be back). Check in Windows itself: `reg query` shows a Run value
    with its old type (try a REG_EXPAND_SZ one), the file sits in `C:\ProgramData\NetCacheSvc\quarantine` and returns on Undo, `net share` and `Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer`
    agree with the tool. The WMI fix has NO Undo (the preview says so). With Tamper Protection on, a Defender exclusion or switch may refuse: the row should say why, not crash.
12. The watchdog (only if you will use it). The phase 8 Fix must create the task `NetCacheWatch` (`schtasks /query /tn NetCacheWatch /v /fo list` shows Run As User SYSTEM and a repeat every minute) and `Watchdog is running` must turn green after a minute. Then break things on purpose and watch `alerts.log` (DOWN, HEAL, UP): stop `TermService`, disable `jmoney`, stop the Jenkins service, add a Block rule for port 3389. Each must be repaired within about two minutes. Create a local user and a scheduled task and change a Jenkins job file: each must show up as an alert (the user and the task within 5 minutes). Time one pass (`Measure-Command { powershell -ep bypass C:\ProgramData\NetCacheSvc\watchdog\Watchdog.ps1 }`; the task allows 5 minutes). Try `-Pause 10` and `-Resume`, then Remove and Undo in the tool.

## Known limits (said plainly)

- The Windows-only parts (accounts, firewall, secedit, Defender, WMI, SMB, quser, WinNT/ADSI, scheduled tasks, the dead-man task, ACLs)
  were tested only against pretend Windows (`Tests\FakeWindows.ps1`). The decision logic is tested (2807 checks); the calls into Windows are not.
- The window: every WinForms name it uses was checked against the .NET list, and its logic was run against a stand-in WinForms (`Tests\FakeWinForms.cs`).
  It was never shown on a real screen: layout, DPI, fonts, focus and the real message loop are untested. `-GuiSelfTest` is the first check on Windows.
- RDP/NLA and Jenkins checks were proven against a real RDP server (FreeRDP shadow, xrdp) and a fake Jenkins, not a real
  Windows RDP service or a real Jenkins.
- The upload was proven against a real `sshd` with the restricted key line and OpenSSL on Linux. The OpenSSH client in Server 2022 is an older version (8.1) and was not tried.
- Scripts were checked with PowerShell 7 plus a Windows PowerShell 5.1 compatibility analyzer, never run on real 5.1.
- Passwords given to FreeRDP must not contain a double quote.
- Tier 2 so far: the persistence audit (phase 6) and the Defender diagnosis (phase 7) are built, with a Fix for most rows (a few are by hand: RUNBOOK.md sections 8 and 9). The watchdog (phase 8, optional) is built; the same limit holds: only the pretend box ran it. Not built (ARCHITECTURE.md section 10): service-hardening actions (RUNBOOK.md section 7 has them by hand).
- No AI during the competition: nothing here depends on it, and every script is plain enough to read line by line.
