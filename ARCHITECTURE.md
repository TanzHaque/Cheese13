---
tags: [hpcc4, windows, scripts, architecture]
status: Tier 1 BUILT and tested against pretend boxes (26 test files, 2807 checks). Never run on real Windows. Tier 2 built: persistence + Defender audit and their fixes, and the optional watchdog; service-hardening actions not built (section 10)
updated: 2026-10-15
---

# HPCC4 hardening tool: how it is built

Target: assembly-t, Windows Server 2022, Windows PowerShell 5.1 (the `powershell.exe` already on the box).
Nothing needs installing on the box. Everything is plain ASCII text with LF line endings so PS 5.1 never misreads a character.
This file describes the code as it is. `README.md` is the map of the folder, `RUNBOOK.md` is the manual for the day.

## 1. The one idea: three layers, one direction

```
  COLLECTORS  ->  JUDGES  ->  FINDINGS  ->  ACTIONS (the only code that changes the box)
  read Windows    decide      a row in      preview -> confirm -> journal -> apply
  (no changes)    (pure)      the grid
```

- **Collector** (`lib\Collect.ps1`) = "what is on the box?" Returns plain objects (users, services, tasks, ports...). Never changes anything.
  Each collector runs inside `Invoke-Collector`, so one that breaks becomes a row "Could not read: ..." instead of stopping the audit.
- **Judge** (`lib\Judge*.ps1`) = "is that a problem?" A pure function: facts and settings in, findings out. No Windows calls, so every judge
  is unit-tested on Linux with made-up facts. This is how it was tested without a Windows machine.
- **Finding** = one row: Phase, Area, Severity (OK / INFO / WARN / BAD), Subject, Why, an optional Fix (the NAME of the function that builds
  the action), a Blocked text ("do this first") and Batch (may "Fix phase" include it?).
- **Action** (`lib\Act-*.ps1`) = `New-Action`: Id, Title, Risk, plain-English Will lines, Data, Capture (read-only old state), Apply, UndoKind,
  NoUndo text, TypeWord, NeedsDeadMan. Building an action changes nothing. Only `Invoke-Change` runs one.
- **Runner / Console / Gui** = glue. `lib\Runner.ps1` is the flow (audit, pick a row, build the action, `Invoke-Change`, read the affected
  parts of the box again). The text menu (`Console.ps1`) and the window (`Gui.ps1`) call only Runner functions, so the flow is tested without a window.

Adding a check later = one collector section + one judge + (optionally) one action. The window code does not change.

## 2. Files (all under `5-HPCC/Scripts/`)

| File | What it is |
|---|---|
| `Start-Hardening.ps1` | Launcher. Loads `lib\` in order, admin check, then window / `-NoGui` / `-NoGui -Apply` / `-Journal` / `-Undo n` / `-UndoLast` / `-GuiSelfTest`. If the window cannot open it falls back to the text menu |
| `lib\Core.ps1` | The plan as constants (`$script:Plan`), settings, journal, `New-Action`, `Invoke-Change`, `Undo-Change`, `Invoke-Native` (runs a program with a time limit, keeps stdout/stderr apart), passwords (`Get-DerivedPassword`, strength rules), SHA-256 |
| `lib\DeadMan.ps1` | Dead-man switch: arm / extend / disarm as actions, status, clock, blocker |
| `lib\Collect.ps1` | All collectors (read-only): Host, Net, Tools, Accounts, Secedit, Services, Tasks, Ports, Firewall, Defender (status, preferences, policy switches), Persist (Run keys, startup folders, Winlogon, IFEO, AppInit, LSA, accessibility programs, WMI, hosts, shares, BITS, profiles, policy scripts, proxy, RDP DLL), Jenkins, Collector (log shipper), Backup, DeadMan. `Get-SectionsForAction` says which parts a change makes stale |
| `lib\Judge.ps1` | The finding type; phase 1 (recon), phase 3 (backup), phase 7 (Defender diagnosis: services, policy switches, switches, exclusions by kind, mode, feature, signatures; report only), phase 9 (routine) |
| `lib\JudgeWatchdog.ps1` | Phase 8: is the watchdog installed and running, which checks fail, what differs from its baseline, its latest alerts, and the control rows. Tells the tool's own task from a fake one (`Get-OwnTaskState` in `JudgeHunt.ps1`: right name, folder `\`, exactly ONE action that contains the expected script path) |
| `lib\JudgeAccounts.ps1`, `JudgeFirewall.ps1`, `JudgeHunt.ps1` | Phases 2, 4 and 6 (services, tasks, ports, connections, and the persistence audit with its summary row `Persistence audit`) |
| `lib\Act-Accounts.ps1` | New admin, confirm, retire (password, groups, disable), enable/repair, rotate jmoney once, demote jmoney, Guest, lockout, RDP logon right |
| `lib\Act-Backup.ps1` | Blackbox IP, SSH key, host key pin, as-found backup (zip + AES-256 + SHA-256 file), `scp` send |
| `lib\Act-Firewall.ps1` | Service, allow 3389/8080, baseline of the three profiles, logging, disable other inbound allows, outbound default-deny |
| `lib\Act-Hunt.ps1` | Quarantine a service or a scheduled task (disable, never delete; the never-touch list and the tool's own tasks are refused in code; a task under `\Microsoft\` only when its command starts a shell or runs from an odd folder) |
| `lib\Act-Persist.ps1` | The fixes for phase 6 persistence rows and phase 7 Defender rows, ONE item each: delete one registry value (from an allow-list of hiding places), quarantine one startup file / profile / policy script, remove one hosts line, one share, one WMI subscription (no Undo), remove one Defender exclusion, switch one kind of scanning back on |
| `lib\Act-Watchdog.ps1` | Install or remove the watchdog task (copies `Watchdog.ps1` and `Panic.ps1` into the data folder, SYSTEM task every minute, reads back the repeat interval and rolls back if it is wrong), and the four small notes: pause, resume, take the baseline again, accept the Jenkins job files |
| `lib\Runner.ps1`, `Console.ps1`, `Gui.ps1` | The flow, the text menu, the WinForms window (about 1000 lines, glue only) |
| `Panic.ps1` | Break glass AND the payload of the dead-man task. Short, typeable |
| `Watchdog.ps1` | The optional watchdog. A standalone script, one pass per run (about 800 lines), run once a minute by the SYSTEM task `NetCacheWatch`. It borrows three repairs from `Panic.ps1` (RDP, jmoney, Jenkins) and adds one of its own (the two firewall allow rules). Everything else only becomes a line in `alerts.log` |
| `ScoreLib.ps1` | Check functions used by `Verify-Hardening.ps1` (`Score-Check.ps1` is an optional extra, not in the bundle) |
| `Verify-Hardening.ps1` + `VerifyFacts.ps1` + `VerifyJudge*.ps1` | Independent read-only proof that each plan decision is true and scoring still passes (section 9) |
| `RUNBOOK.md` | The printed manual: card, phases, "By hand" blocks, blackbox setup, break glass |
| `Lab\*` | Lab VM only: `Reset-LabInsecure.ps1` plants random problems with an encrypted answer key; `LabGrade.ps1` grades |
| `Tests\*` | 26 test files, `Run-AllTests.ps1`, the pretend Windows (`FakeWindows.ps1`), the stand-in WinForms (`FakeWinForms.cs`) and the .NET name lists. Not deployed to the box |

Data on the box: `C:\ProgramData\NetCacheSvc` (only SYSTEM and Administrators): `journal\`, `deadman\`, `backup\`, `ssh\`, `settings.json`,
`watchdog\`, `rights-before.inf`, `tools\`, `quarantine\`. Settings: NewAdmin, NewAdminConfirmed, ExtraKeep, TeamNet, BlackboxIp, BackupUser (default `uploader`),
DeadManMinutes (5), JmoneyRotations.

## 3. The safety pipeline (`Invoke-Change`) - every change goes through it

1. **Gate**: refuses unless "Allow changes" is on. Checked in code, not just by greying buttons. The tool starts in AUDIT (read-only).
2. **Dead-man check** (firewall-type actions only): `Get-DeadManBlocker` must be empty: the switch is armed and has more than 60 seconds left.
   It is checked again after you answered, because reading the preview can take minutes.
3. **Preview + confirm**: plain-English text built from the action itself (what changes, whether Undo exists, what cannot be undone).
   Yes/No, default No. High-risk actions make you type a word (`jmoney`, `RDP`, `OUTBOUND`, `ROTATE AGAIN`, your own account name, or `APPLY`).
4. **Capture**: a read-only read of the old state. If it fails nothing is changed.
5. **Journal**: `journal\NNNN.json` is written (status `started`) BEFORE the change.
6. **Apply** inside try/catch with `$ErrorActionPreference = 'Stop'`: a cmdlet that fails halfway fails the whole change. Status becomes `applied` or `failed`.
7. **Undo**: `Undo-Change` finds the handler by NAME (`Register-UndoHandler`), so a journal file from an earlier run can still be undone. Same gate and confirm.

## 4. Dead-man switch (`lib\DeadMan.ps1`, `Panic.ps1`)

- **Arm**: `netsh advfirewall export` to `deadman\fw-before.wfw`, a private copy of `Panic.ps1`, the list of adapters that are up, then a one-time SYSTEM
  scheduled task `NetCacheRestore` for T+N minutes (default 5) that runs the copy with `-FromTask`. It does not depend on the window or on your RDP session.
  Arming again only extends: the saved export is never overwritten by a policy that might already be broken.
- **Gate**: firewall-type actions refuse unless armed with more than 60 seconds left (section 3, step 2).
- **Disarm** = "Keep changes": removes the task. Do it only after NEIGH is green.
- `Panic.ps1`: imports the saved policy (or resets to the Windows default plus the two allow rules), switches adapters on, allows RDP and starts TermService,
  enables `jmoney` and puts it in Remote Desktop Users (password untouched), starts Jenkins, restores the old RDP logon right, checks 3389 and 8080.
  Each step can be run alone (`-Only Firewall|Adapters|Rdp|Jmoney|Jenkins|Rights`). It logs to `deadman\panic.log`.
- Limit I cannot remove: the Red Team can delete a scheduled task. `Get-DeadManStatus` notices a missing task ("someone deleted it?"); the watchdog does not check it either (it ignores the tool's own two tasks), so look at the dead-man row in the window.

## 5. Decisions built in as code, not as options

- Accounts are **never deleted**. There is no `Remove-LocalUser` in the tool. Order: new password -> remove from privileged groups -> disable.
- The old admins are only touched after the new admin is **confirmed** (you logged in with it in a second RDP session).
- Passwords come from the **laptop** (Bitwarden). The tool has hidden prompts only; secrets live in memory (`$script:Hp.Secrets`) and are never written anywhere.
  Retired accounts get `HMAC-SHA256(master, lower-case name)` as base64, first 24 characters, plus `aA1!`; the laptop can recompute any of them.
- **jmoney** is rotated once; a second rotation needs `ROTATE AGAIN`. No action can disable it, delete it or take it out of Remote Desktop Users (`Assert-NotScoringUser`).
- **No lockout policy.** If lockout is on, the audit flags it and the fix sets the threshold to 0.
- **No auto-kill.** No action kills a process. Quarantine disables a service or task; the protected list (Jenkins, Java, TermService, the log collector, Windows
  components, the tool's own dead-man task) is checked again when the old state is read, not only in the judge.
- Firewall: inbound allow rules for 3389 and 8080 have **no source restriction**; other inbound allow rules are **disabled, never deleted**; Core Networking is
  never touched; the only rules the tool removes are its own `HP-*` rules; nothing runs before the two allow rules exist (`Assert-ScoredPortsAllowed`).
- Persistence and Defender fixes (`lib\Act-Persist.ps1`) remove **ONE thing at a time** and none of them is in "Fix phase" (`Batch = $false`), except the Defender ones (an exclusion, a switch, a policy value),
  which are ordered so the policy value goes before the switch it blocks. A registry value is touched only if its key AND name are on an allow-list (`$script:RegistryFixRules`: Run/RunOnce,
  IFEO `Debugger`, SilentProcessExit, AppInit/Load/Run, Winlogon, the nine Defender policy names). The list is checked BEFORE the value is read and again with the value, so a wildcard name,
  an unlisted name, the unnamed (Default) value or a Run entry that starts Jenkins is refused even if a finding pointed at it. Winlogon `Shell`, `Userinit` and `AppInit_DLLs` are SET back to the Windows
  default, never deleted (a missing value breaks logon); the Winlogon ones are High risk and need the word `WINLOGON`. The old value is saved WITH its type (String, ExpandString, DWord) and Undo writes the same type back.
- Files are **moved, never deleted**: a Startup-folder file, a PowerShell profile or a local policy script goes to `quarantine\<time>-<name>`, SHA-256 checked after the move; Undo refuses if the
  original path is taken. A WMI subscription is the exception on Undo: its details go to the journal, but nothing recreates it (the preview says so; a new binding needs a human). Shares named
  `ADMIN$`, `IPC$`, a drive letter `C$` or any special share are refused.
- Scheduled tasks under `\Microsoft\` are skipped by the audit unless `Test-SuspiciousMicrosoftTask` says so (the command starts a shell or runs from an odd folder), and `Assert-TaskMayChange` applies
  the same words when the task is read. This is a words-only guard on purpose: the red team and the lab hide tasks there, and the program-path guard refused System32 programs that the judge had flagged.
- The watchdog (`Watchdog.ps1`) repairs ONLY the four scored things (Remote Desktop, `jmoney`, Jenkins, the two allow rules) and only by switching things ON or rebuilding its own `HP-Allow-TCP-*` rules; it disables a Block rule only when it stops a scored port for every address. It never sets a password, deletes an account or kills a process (a test reads the code for this). The tool's own tasks `NetCacheWatch` and `NetCacheRestore` are recognised by name, folder and exactly one action with the expected script path; a task that only borrows the name shows as BAD with no button, and no action will change it. The task runs a private copy in the data folder (only SYSTEM and Administrators can write there). Jenkins job files are watched, never rewritten by itself.
- Backup: **blackbox only** (rule 3), IP as numbers, host key pinned from the blackbox console (no trust on first use), restricted upload user (`uploader`,
  `restrict,command="scp -t /srv/backup/incoming"`), archive encrypted with AES-256 and opened ON blackbox. The tool says in its own words that it cannot read the file back.

## 6. The window and the text menu

`Gui.ps1` is glue: every button calls a Runner function; every change still goes through `Invoke-Change`. The controls of the main window live in
`$script:Ui`, those of the open dialog in `$script:Dlg`; event handlers use only those and functions. Every handler runs through `Invoke-GuiAction`, so a mistake inside
one is logged and shown and the window keeps working. It is synchronous with a status bar: no background threads to debug. The file has no commands at the top level and loads
WinForms when the window opens, so the tests can load it on a machine without WinForms. WinForms was chosen because it ships with Server 2022, works in RDP and on the NEIGH
Console, needs no downloads, and `button.Add_Click({ ... })` is easy to explain.
Window: top bar = Allow changes, mode text, dead-man countdown with Arm / Extend / Keep changes; second bar = Phase box,
"Only BAD and WARN", Re-audit, Fix selected, Fix phase..., Undo last, Undo..., Journal..., Help; centre = the rows; below = the explanation of the selected row and the log.
The X button asks before closing while the dead-man switch is armed or a job runs. `Start-Hardening.ps1 -GuiSelfTest` builds the window and every dialog on the machine without showing anything.

## 7. How each thing is tested (26 files, 2807 checks, all passing at the last run)

1. Parse + PSScriptAnalyzer lint of every script (PowerShell 7.6 + PSScriptAnalyzer 1.25): clean on all 34 deliverable scripts.
2. **PS 5.1 compatibility lint**: `PSUseCompatibleSyntax/Commands/Types` against the Windows PowerShell 5.1 profile, so nothing PS 7-only sneaks in.
3. **Pretend Windows** (`Tests\FakeWindows.ps1`): stand-ins for the cmdlets and commands the tool calls, all reading and changing one state object. Each stand-in declares the
   real parameter names, so a call with a wrong parameter name fails in the test like on Windows. The REAL collectors, judges, actions, gate and runner run on top of it.
4. **Real programs where Linux has them**: real `sshd`, `scp`, `ssh-keygen`, `ssh-keyscan` with the restricted key line (`Test-BackupTransfer.ps1`: a swapped host key, an impostor server,
   an unpinned host and a wrong client key all fail and nothing arrives); real OpenSSL opens the archives (`Test-ActBackup.ps1`); real PowerShell child processes test `Invoke-Native`;
   a real RDP server (FreeRDP shadow / xrdp) and a fake Jenkins test `Score-Check` (an optional extra).
5. **The window**: `Test-GuiApi.ps1` checks every WinForms name used in `Gui.ps1` (controls, properties, methods, events, enum words, constructor argument counts) against a list dumped from
   the .NET assemblies; `Test-GuiApiMutations.ps1` proves that checker can fail by planting mistakes; `Test-Gui.ps1` runs the window code against a stand-in WinForms (`FakeWinForms.cs`)
   with a scripted "person" who clicks, ticks and answers dialogs.
6. **House rules** (`Test-CodeRules.ps1`, 13 rules): parses, ASCII, LF; one spelling per variable in a function (PowerShell ignores case); check scripts only read; only the lab files
   mention the answer key; only actions change the box (a changing command may appear only inside `New-Action` / `Register-UndoHandler` blocks or a short named helper list);
   collectors only read; judges are pure; only `Core.ps1` runs an action; a launcher or test must not reuse a library's script-level variable name; glue files change nothing themselves;
   `New-*` functions only build; `Watchdog.ps1` and `Panic.ps1` (they run as SYSTEM with nobody watching) may change things only in the listed functions, never set a password, borrow only three repairs, and write a job file only in `-RestoreJob`; every test file turns an error that nothing caught into a failure (a crashing check cannot silently disappear).
7. **Not testable by me**: anything that calls real Windows (firewall, local users, secedit, scheduled tasks, Defender, WMI, ACLs, Jenkins) and anything that shows a window. Those get tested
   in your lab; `README.md` has the first-run list. The in-box OpenSSH 8.1 client was not tried, and Mono's WinForms list stands in for the .NET Framework one.

## 8. Extras (item 4 of the brief)

| # | Extra | Status |
|---|---|---|
| E1 | `Panic.ps1` | **built, tested** (also the dead-man payload) |
| E2 | `New-HpccSecrets.ps1` | **not needed**: you generate passwords in Bitwarden |
| E3 | `Stage-Bundle.ps1` | not selected; `RUNBOOK.md` 1.1 has the three-line bundle command instead |
| E4 | `RUNBOOK.md` | **written** (printable); commands outside the tool were not run on Windows |
| E5 | `lab-blackbox-setup.sh` | deferred; `RUNBOOK.md` 5.1 has the blackbox setup lines, and `Test-BackupTransfer.ps1` proves the upload against a real sshd |
| E6 | Watchdog | **built, optional** (`Watchdog.ps1`, phase 8); tested only against the pretend box (`Test-Watchdog.ps1`, `Test-ActWatchdog.ps1`) |

## 9. Verification tooling (built before the hardening tool, because it is how the tool gets proven)

**`Verify-Hardening.ps1`** runs ON the box, elevated, and changes nothing (one exception in the lab: `-Lab -WatchMinutes` empties the lab beacon log first). It prints
PASS / FAIL / WARN / INFO / SKIP lines in sections: Scoring, Accounts and passwords, Firewall, RDP and services, Defender and Windows settings, Leftovers. Exit code 0 = all PASS,
1 = a FAIL, 2 = only WARN / SKIP. It also tries each packet default password once per enabled account (skipped if a lockout policy exists or cannot be read, so it cannot lock anyone out).

**Deliberately independent of the hardening tool.** Verify has its OWN collectors (`VerifyFacts.ps1`) and judges (`VerifyJudgeAccounts/Firewall/System.ps1`). The tool has separate ones
(`lib\Collect.ps1`, `lib\Judge*.ps1`). Two implementations of "is the firewall right?" means one bug cannot make both tools wrong in the same way. The judges are pure functions (facts
in, results out), so they are tested on Linux with fake boxes. The collectors are the thin Windows layer that cannot be tested off-box.

**What Verify catches that a port scan cannot**: a STIG-style policy that denies jmoney the network logon right (NLA then refuses the scoring login while port 3389 still looks open),
a firewall allow rule restricted to certain source IPs, a rule that is only active on the wrong network profile, a blanket Public block, a hijacked `termsrv.dll`, Defender exclusions,
a lockout threshold, only two free RDP session slots.

**The inside-the-box limit**: Verify cannot do the real RDP login (it would go through loopback, not the firewall). Look at NEIGH as well; that is the closest
thing to the scoring engine.

**Lab only**: `Lab\Reset-LabInsecure.ps1` plants a random set of problems and writes the answer key encrypted with a passphrase you type. `Verify-Hardening.ps1 -Lab` asks for the
passphrase and grades each planted item FIXED / PARTIAL / MISSED / UNKNOWN. The hardening tool contains no code that references the key; `Test-CodeRules.ps1` fails if any file outside
`Lab\`, `Tests\` and `Verify-Hardening.ps1` mentions it.

## 10. What is NOT built yet (Tier 2) and where it would plug in

| Item | Today | Where it plugs in |
|---|---|---|
| Persistence audit | **BUILT** (`Get-PersistFacts` + `Get-PersistHuntFindings`; tested in `Test-Persist.ps1`). Fixes **BUILT** in `Act-Persist.ps1` (tested in `Test-ActPersist.ps1`): one value / file / line / share / subscription per click, Undo for all but WMI. Not fixed by the tool (by hand, `RUNBOOK.md` section 8): LSA packages, accessibility-program replacement, BITS jobs, the proxy, a changed RDP DLL | -- |
| Defender repair | Diagnosis **BUILT** (services, policy switches, real-time/behavior/downloads, exclusions by kind, mode, other antivirus, feature, signatures, tamper, last scan). Fixes **BUILT** for exclusions, the three scanning switches and the nine policy values (`def.*` actions). Not fixed by the tool: passive mode caused by another antivirus, Tamper Protection, missing signatures (`RUNBOOK.md` section 9) | -- |
| Watchdog | **BUILT** (optional): `Watchdog.ps1`, `JudgeWatchdog.ps1`, `Act-Watchdog.ps1`; `RUNBOOK.md` section 10. Not built: automatic restore of Jenkins job files, periodic backups from the task | -- |
| Service hardening for RDP and Jenkins | Manual, one change at a time (`RUNBOOK.md` section 7) | actions with Capture/Undo, NEIGH after each |
| DISA GPOs | Lab-gated, not built | only after a lab pass |
