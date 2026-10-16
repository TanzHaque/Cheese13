---
tags: [hpcc4, windows, runbook]
updated: 2026-10-15
---

# HPCC4 RUNBOOK - assembly-t (Windows Server 2022)

Print this. On competition day there is **no AI at all** (packet rule 6, and your own rule). This file, `0-Gameplan.md` and the scripts are all you have - read them tonight.

- Team number: **t = ____**   assembly = `172.16.t.30`, blackbox = `172.16.t.5`. Replace `t` in every command (write it on the paper copy with a pen).
- Bundle hash (first 16 characters of the SHA-256 of `hp.zip`, written after the Friday freeze): `________________`
- Page 1 (section 0) is the card. The rest is reference, in phase order. "By hand" blocks are only for when the tool will not run.

**Honest status.** Nothing in this file was run on a real Windows Server, a real Jenkins or the real blackbox. The tool's code passed its 26 test files (2807 checks) on Linux with PowerShell 7 and a pretend Windows box. Two parts used real programs on Linux: the archive encryption opens with real OpenSSL (`Tests\Test-ActBackup.ps1`), and the upload works with a real `sshd`, real `scp` and the restricted key line (`Tests\Test-BackupTransfer.ps1`). NOT run anywhere: the blackbox setup lines, the optional mover script (5.4), every "By hand" block, the checks in sections 7-9, and the watchdog (section 10: the scheduled task, the event IDs, how long a pass takes). Rehearse all of it in the lab. A step you cannot explain, or that fails, gets fixed in the lab, not on the day.

---

## 0. The card

Open an ELEVATED Windows PowerShell (Start, type `powershell`, right-click, Run as administrator), then:

```powershell
cd C:\hp
```

| Type this | What it does |
|---|---|
| `powershell -ep bypass .\Start-Hardening.ps1` | The window. It starts READ-ONLY; tick "Allow changes" to change anything |
| `powershell -ep bypass .\Start-Hardening.ps1 -NoGui` | Print the audit and stop (read-only) |
| `powershell -ep bypass .\Start-Hardening.ps1 -NoGui -Phase 2` | Only phase 2 |
| `powershell -ep bypass .\Start-Hardening.ps1 -NoGui -Apply` | Text menu: same checks, asks before every change |
| `powershell -ep bypass .\Start-Hardening.ps1 -Journal` | List every change made so far |
| `powershell -ep bypass .\Start-Hardening.ps1 -Undo 12` | Undo change number 12 (asks first) |
| `powershell -ep bypass .\Start-Hardening.ps1 -UndoLast` | Undo the newest change that can be undone |
| `powershell -ep bypass .\Start-Hardening.ps1 -GuiSelfTest` | Check that the window builds here (shows nothing, changes nothing) |
| `powershell -ep bypass .\Panic.ps1` | BREAK GLASS: firewall back, RDP on, jmoney on, Jenkins running |
| `powershell -ep bypass .\Panic.ps1 -Only Firewall` | Just one step: Firewall, Adapters, Rdp, Jmoney, Jenkins or Rights |
| `powershell -ep bypass C:\ProgramData\NetCacheSvc\watchdog\Watchdog.ps1 -Status` | Only if you installed the watchdog (section 10): last pass, checks, last alerts |
| `powershell -ep bypass C:\ProgramData\NetCacheSvc\watchdog\Watchdog.ps1 -Pause 10` | The watchdog repairs nothing for 10 minutes. Do this BEFORE you change RDP, jmoney, Jenkins or the allow rules on purpose. `-Resume` ends it |

Text menu keys: **row number** = fix that row, **p 2** = fix phase 2, **a** = audit again, **d arm** / **d extend** / **d keep** = dead-man switch, **u** = undo last, **j** = journal, **c** = changes on/off, **q** = quit.

Window buttons: tick **Allow changes**; **Arm** / **Extend** / **Keep changes** (dead-man); **Phase** box; **Only BAD and WARN** (ticked = hides the green rows); **Re-audit**; **Fix selected**; **Fix phase...**; **Undo last**; **Undo...**; **Journal...**; **Help**.

Typed words for HIGH-RISK changes (exact capitals): `jmoney` (change/demote jmoney), `RDP` (limit the RDP logon right), `OUTBOUND` (outbound default-deny), `ROTATE AGAIN` (second jmoney change), `WINLOGON` (set the Winlogon Shell or Userinit back to the Windows default), your own account name (retiring the account you are logged in as), `APPLY` (default).

Colors: red BAD, yellow WARN, gray INFO, green OK. `[fix]` = the tool can fix it. "cannot be fixed yet" = read the reason, it names the step to do first.

**The rules that bite**
- Never log in as `jmoney`. Never disable or delete `jmoney`. Never change ports 3389 or 8080. Never touch Jenkins, Java, TermService or the log collector.
- Firewall changes only with the dead-man switch ARMED. "Keep changes" only after: NEIGH green for two cycles, and `rocket-build` SUCCESS.
- If the watchdog runs, it puts Remote Desktop, `jmoney`, Jenkins and the two allow rules back within a minute. Pause it (card) before you change one of them on purpose.
- Keep ONE RDP session of your own open. The box allows 2 remote sessions in total and a *disconnected* session still holds a slot, so scoring can be refused. Sign out, do not just close the window.
- Data goes to blackbox only (rule 3). Never copy a backup to the laptop. Open archives ON blackbox.
- Passwords come from Bitwarden. Never type a password into a command line (`net user bob Secret1` is logged). Never save one in a file on the box.
- No AI. Injects in your own words.

---

## 1. Before the competition (Friday)

### 1.1 Freeze and bundle (laptop, PowerShell)

The competition bundle holds only what the box needs. `Lab\` and `Tests\` stay on the laptop.

```powershell
cd "C:\Users\Blaze\OneDrive\Desktop\Personal Vault\3-CyberTec\5-HPCC\Scripts"
$f = 'Start-Hardening.ps1', 'Panic.ps1', 'Watchdog.ps1', 'ScoreLib.ps1',
     'Verify-Hardening.ps1', 'VerifyFacts.ps1', 'VerifyJudgeAccounts.ps1',
     'VerifyJudgeFirewall.ps1', 'VerifyJudgeSystem.ps1', 'lib'
Compress-Archive -Path $f -DestinationPath "$env:USERPROFILE\Desktop\hp.zip" -Force
(Get-FileHash "$env:USERPROFILE\Desktop\hp.zip").Hash
```

Write the first 16 characters at the top of this page. Any change to any script changes the hash: rebuild and rewrite it.

### 1.2 Lab rehearsal (again after the freeze)

1. On the lab VM copy the whole `Scripts` folder (not the bundle) to `C:\hp`. Run `powershell -ep bypass C:\hp\Tests\Run-AllTests.ps1` and `powershell -ep bypass C:\hp\Start-Hardening.ps1 -GuiSelfTest` (must say OK). Every test file should say `ok`; `Test-BackupTransfer` and `Test-Gui` show `0 passed` because they need Linux, that is normal. The tests passed on Linux, so a FAIL here is a Windows difference: keep the FAIL lines and get it fixed BEFORE the Friday freeze.
2. Revert the `clean-lab` snapshot, run `Lab\Reset-LabInsecure.ps1 -IAmInTheLab`, then do phases 1, 2 and 4 with a stopwatch. Goal: phases 1 and 2 in under 10 minutes.
3. Rehearse on purpose: let the dead-man switch FIRE once; run `Panic.ps1`; `-UndoLast`; type the card commands on the NEIGH Console (no paste there). If you will use the watchdog (section 10): install it, break things on purpose (stop `TermService`, disable `jmoney`, stop Jenkins, add a Block rule for port 3389) and watch it repair them within about two minutes (`alerts.log`: DOWN, HEAL, UP); time one pass. If anything there surprises you, do not use it on the day.
4. `Verify-Hardening.ps1` on the box after each phase (section 11), and a look at NEIGH.

### 1.3 Bitwarden items to make now (laptop only - never on the box)

| Item | How to make it | Used for |
|---|---|---|
| new admin name | 1-20 characters: letters, digits, `.` `_` `-`. Nothing obvious | Phase 2 |
| new admin passphrase | Passphrase generator: 5+ words + digits, plain keyboard characters (you must TYPE it on the Console). Make 5 spares, number them | Phase 2, then a new one about every 2 hours |
| jmoney password | Password generator: 32 characters, letters and digits only (the scoring engine pastes it into logins; quotes, spaces, `$` and backslash can break it) | Phase 2, NEIGH, Jenkins |
| throwaway master | 20+ random characters | Phase 2: retired accounts get passwords derived from it (appendix B) |
| backup passphrase | 16+ characters | Phase 3: opens the archives. Lose it and the backups are useless |
| blackbox admin password | new, replaces the packet default | Phase 3 |

### 1.4 Laptop checks

- NetBird connected; `mstsc` and `ssh -V` work.

### 1.5 Print

This file, the phase pages of `0-Gameplan.md`, the NEIGH steps (section 4, jmoney) and the revert steps (section 9).

---

## 2. Start of the day (first 5 minutes)

1. Laptop (NetBird on): `mstsc /v:172.16.t.30`. Log in as `plinktern` with the packet password (packet pp. 12-13).
2. NEIGH, Boxes, assembly, Console: check it opens (each link works once; a black screen means use RDP or press Restart). Close it.
3. NEIGH, Scoring: screenshot what is green. That is the baseline.
4. Get the bundle onto the box, any one of:
   - In the mstsc window: copy `hp.zip` on the laptop (Ctrl+C), click the RDP desktop, paste (Ctrl+V).
   - Before connecting: mstsc, Show Options, Local Resources, More, tick drive C. In the session copy `\\tsclient\C\Users\Blaze\Desktop\hp.zip` to the Desktop.
   - Plan B (blackbox hands it over): laptop: `ssh plinktern@172.16.t.5 mkdir -p depot`, then `scp "$env:USERPROFILE\Desktop\hp.zip" plinktern@172.16.t.5:depot/`, then `ssh plinktern@172.16.t.5` and there `cd depot` and `python3 -m http.server 8000 --bind 172.16.t.5`. On the box: `Invoke-WebRequest http://172.16.t.5:8000/hp.zip -OutFile "$env:USERPROFILE\Desktop\hp.zip" -UseBasicParsing`. Stop the server with Ctrl+C when it is done.
5. On the box, elevated PowerShell:

```powershell
cd $env:USERPROFILE\Desktop
(Get-FileHash .\hp.zip).Hash.Substring(0,16)
```

It must be IDENTICAL to the 16 characters at the top of this page. If not: stop, copy it again.

```powershell
Expand-Archive .\hp.zip C:\hp -Force
icacls C:\hp /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"
cd C:\hp
powershell -ep bypass .\Start-Hardening.ps1 -NoGui
```

The `icacls` line stops ordinary users from editing the scripts you are about to trust. The first audit takes up to a minute. Then open the window: `powershell -ep bypass .\Start-Hardening.ps1`.

If the window does not open it prints why and starts the text menu by itself. Same tool, same safety checks.

---

## 3. Phase 1 - Recon (read-only)

Read the phase 1 rows top to bottom. Write down on paper:

- Team number and team network (row "Team network").
- Jenkins service name, the account it runs as, and JENKINS_HOME (rows under "Jenkins"). Leave all three as they are.
- Row "Scripts in init.groovy.d": every file there runs each time Jenkins starts. Read each one.
- Row "Log collector found": it ships the event logs to blackbox. NEVER stop or block it.
- Row "Internet": if it is reachable, download tools NOW, before outbound deny (below).
- Row "PowerShell and .NET": the release must be 461808 or higher or the backup encryption fails.
- Row "Network profile is Public": note it, it is why firewall rules may not apply as you expect.

Tools to download while the Internet is open (Sysinternals, Defender offline signatures). Do not run anything from them yet:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$d = "C:\ProgramData\NetCacheSvc\tools"
New-Item -ItemType Directory -Force $d | Out-Null
Invoke-WebRequest https://download.sysinternals.com/files/SysinternalsSuite.zip -OutFile $d\si.zip -UseBasicParsing
Invoke-WebRequest "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64" -OutFile $d\mpam-fe.exe -UseBasicParsing
Expand-Archive $d\si.zip $d\si -Force
Get-ChildItem $d -Recurse -Include *.exe | Get-AuthenticodeSignature | Where-Object Status -ne Valid
```

The last line must print nothing. Check both URLs once in the lab.

OpenSSH client (the Backup rows turn red if it is missing). Check: `where.exe ssh scp ssh-keygen ssh-keyscan`. Install while the Internet is open:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

No Internet: copy the four `.exe` files from `C:\Windows\System32\OpenSSH` on the laptop into the same folder on the box.

---

## 4. Phase 2 - Accounts (first 10 minutes, highest priority)

Run the tool as plinktern for the first step only. The order matters: the old admins are touched only after the new one is confirmed.

**4.1 New admin.** Row "No new admin account yet", Fix. It asks for the name and the passphrase twice (hidden prompts; paste them from Bitwarden). Read the preview, Yes. The preview warns if the passphrase is short or not plain keyboard characters.

**4.2 Confirm it (do not skip).**
1. Laptop: a SECOND mstsc window: `mstsc /v:172.16.t.30`, log in as the new admin. If it fails, fix it from the first window and do not go on.
2. In the new session open an elevated PowerShell (Run as administrator), `cd C:\hp`, start the tool there. It remembers the name (settings file). Row `New admin 'name' not confirmed yet`, Fix, Yes. That is "Confirm".
3. Sign out of the plinktern session so only ONE session of yours is left:

```powershell
qwinsta
logoff 2
```

Use the ID next to `plinktern` instead of `2`. From now on work in the new admin's session. The tool forgets secrets when it closes, so it asks for them again when needed.

**4.3 jmoney - rotate ONCE.** Have NEIGH open first (scoreboard.plinko.horse, Users). Jenkins has its own `jmoney` login, separate from Windows, so there are two things to change and, in NEIGH, every assembly entry for jmoney (RDP and Jenkins).
1. Row "jmoney still has the packet password", Fix. Paste the Bitwarden password twice. Read the preview, type `jmoney`, Yes.
2. IMMEDIATELY: NEIGH, Users, every assembly entry for jmoney, paste the same password, **Save**.
3. Jenkins (`http://172.16.t.30:8080`, log in with the Jenkins `plinktern` login): People, jmoney, Configure, Password = the same new password, Save.
4. Wait for two green cycles for RDP and Jenkins in NEIGH.
5. Look at NEIGH once more: RDP and Jenkins green.
6. Give the Jenkins `plinktern` login a new random password too (Bitwarden): People, plinktern, Configure.

NEIGH rejects password changes while scoring is paused (lunch). Do not change jmoney a second time unless you must; the tool asks you to type `ROTATE AGAIN`.

If the row says jmoney is an Administrator: "Demote" adds it to Remote Desktop Users first, then removes it from Administrators. Look at NEIGH right after. If the RDP login fails, Undo last.

**4.4 Retire the other accounts** (disable, never delete). Order: built-in Administrator, then `plinktern`, then every other row. For each: Fix. The tool asks once for the throwaway master (Bitwarden, 16+ characters), then for each account sets a derived password, removes it from Administrators / Remote Desktop Users / other groups, and disables it. Rows say "(service account)" or "(kept)" when something runs as that account; leave those alone.

- A row "blocked" tells you what to do first. Typical: "A service runs as this account". If Jenkins runs as `plinktern`, do NOT disable it. Add it to `ExtraKeep` (below) and change its password later through services.msc, Log On tab (so the password never touches a command line).
- Retiring the account you are logged in as is HIGH risk and asks for its name. Do not.

```powershell
notepad C:\ProgramData\NetCacheSvc\settings.json
```

Add the name to the list, keep the JSON valid, for example `"ExtraKeep": ["svc_name"]`, then Re-audit.

**4.5 The small ones.** Row "Guest is enabled", Fix. Row "Account lockout is ON", Fix (the plan uses long random passwords, no lockout - lockout lets the Red Team lock out jmoney). Row "Remote Desktop logon is open to more than the plan allows", Fix: only the new admin and jmoney may log on through RDP afterwards. HIGH risk, type `RDP`. Do it last, with your new-admin session already open. Then look at NEIGH.

**4.6 Check.** On the box: `powershell -ep bypass C:\hp\Verify-Hardening.ps1 -NewAdmin <newadmin> -AskPassword` (the Accounts section must have no FAIL).

### By hand (only if the tool will not run)

Each `*` makes the command ask for the password itself (hidden). Pick names from Bitwarden.

```powershell
net user <newadmin> * /add
net localgroup Administrators <newadmin> /add
net localgroup "Remote Desktop Users" <newadmin> /add
```

Log in as the new admin in a second window and sign out of plinktern. Then:

```powershell
net user Administrator *
net user Administrator /active:no
net user plinktern *
net localgroup Administrators plinktern /delete
net localgroup "Remote Desktop Users" plinktern /delete
net user plinktern /active:no
net user Guest /active:no
net accounts /lockoutthreshold:0
net user jmoney *
```

Do the `jmoney` line once, then NEIGH and Jenkins as in 4.3. Limit the RDP logon right in `secpol.msc`: Local Policies, User Rights Assignment, "Allow log on through Remote Desktop Services": remove the groups, add the new admin and jmoney. Last, with your session already open.

---

## 5. Phase 3 - Backup and blackbox

Rows: OpenSSH client, Blackbox IP, backup key, host key, as-found backup, send.

**Order of play.** The gameplan does phase 2 first. The LOCAL as-found backup takes about a minute, has no network part, and records the original users and groups, so take it before the first account change if you can spare the minute. Decide that before the day. The blackbox part can wait until the firewall is done.

### 5.1 Blackbox (from the laptop)

```powershell
ssh plinktern@172.16.t.5
```

Packet default password the first time. Then, on blackbox:

```bash
passwd
sudo useradd -m -s /bin/bash uploader
sudo usermod -p '*' uploader
sudo install -d -o uploader -g uploader -m 700 /srv/backup/incoming
sudo install -d -o uploader -g uploader -m 700 /home/uploader/.ssh
```

- `passwd`: change blackbox's own default password first (Bitwarden).
- The account is called `uploader`, not `backup`: Debian, Ubuntu and Mint already have a system account called `backup`.
- `usermod -p '*'`: no password works, but a key does (a locked `!` password can make sshd refuse key logins).
- Folder owned by `uploader`, mode 700.

Check that sshd lets the new user in:

```bash
sudo sshd -T | grep -i -E "allowusers|allowgroups|passwordauthentication|pubkeyauthentication"
```

If `allowusers` or `allowgroups` is listed, add `uploader` to it in `/etc/ssh/sshd_config`, then `sudo systemctl reload ssh`.

### 5.2 Key, key line, host key

1. Tool: row "No backup SSH key yet", Fix. The result shows ONE line that starts `restrict,command="scp -t /srv/backup/incoming" ssh-ed25519 AAAA...`. The key is also on the box at `C:\ProgramData\NetCacheSvc\ssh\id_backup.pub`.
2. Copy that whole line (RDP clipboard). On blackbox, from the laptop's SSH window, paste it between the quotes:

```bash
echo 'restrict,command="scp -t /srv/backup/incoming" ssh-ed25519 AAAA...' | sudo -u uploader tee /home/uploader/.ssh/authorized_keys
sudo chmod 600 /home/uploader/.ssh/authorized_keys
```

   `restrict` switches off everything but the forced command: the key can only upload into one folder. The private key never leaves the box.
3. Host key. On the blackbox CONSOLE (NEIGH, Boxes, blackbox, Console - not over the network):

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

   If it says "No such file", list them all: `for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf $f; done`.
4. Tool: row "Blackbox IP not entered", Fix: type the IP as numbers (never a name). Then row "Blackbox host key not pinned", Fix: type the fingerprint (the whole line or the `SHA256:...` part). The tool asks blackbox for its keys and accepts ONLY the one with that fingerprint. "NOT PINNED" means you typed it wrong or something else answers on that address: do not send backups there.

### 5.3 Take, send, verify

1. Row "No as-found backup yet", Fix. Backup passphrase from Bitwarden, twice. About a minute. The archive is encrypted and stays local (`C:\ProgramData\NetCacheSvc\backup`). The passphrase is not saved.
2. Row "Nothing sent to blackbox yet", Fix (needs outbound TCP 22 to blackbox; the outbound rule for the team network covers it). Do the first send EARLY so you know it works.
3. Verify from the laptop. Only hashes come back, no data. `sudo find` does the searching as root: the upload folder is closed to every other user, so a plain `*.enc` typed in your own shell would match nothing.

```powershell
ssh -t plinktern@172.16.t.5 "sudo find /srv/backup -name '*.enc' -exec sha256sum {} +"
```

   Find the line with the archive's name. Its hash must equal the SHA-256 the tool printed.
4. Open an archive ON blackbox, never on the laptop (rule 3). `N` is the archive name (if you set up 5.4, the file is in `/srv/backup/vault/as-found-20261017-100500/` instead of `incoming`):

```bash
sudo -i
umask 077
mkdir -p /srv/backup/work
cd /srv/backup/work
N=as-found-20261017-100500.zip.enc
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -md sha256 -in /srv/backup/incoming/$N -out ${N%.enc}
unzip -l ${N%.enc}
```

   It asks for the backup passphrase. "bad decrypt" or a broken zip means a wrong passphrase. Afterwards: `cd /; rm -rf /srv/backup/work`.
5. The firewall export is inside every backup (`firewall.wfw`). Take another backup after each big change (accounts, firewall, hunt) and send it.

### 5.4 Optional: protect the backups from a stolen key

The upload key lives on a box the Red Team attacks. With it they can only upload, but they could overwrite a file with the same name. This root job moves every finished arrival into a folder the upload account cannot touch. Do it only after everything else works, and test it with a dummy file.

```bash
sudo install -d -m 700 /srv/backup/vault
sudo nano /usr/local/sbin/hp-collect.sh
```

```bash
#!/bin/bash
IN=/srv/backup/incoming
OUT=/srv/backup/vault
now=$(date +%s)
for f in "$IN"/*; do
    [ -f "$f" ] || continue
    age=$(( now - $(stat -c %Y "$f") ))
    [ "$age" -ge 20 ] || continue
    name=$(basename "$f")
    base=${name%.sha256}
    base=${base%.zip.enc}
    mkdir -p "$OUT/$base"
    mv -n "$f" "$OUT/$base/"
done
```

```bash
sudo chmod 700 /usr/local/sbin/hp-collect.sh
echo '* * * * * root /usr/local/sbin/hp-collect.sh' | sudo tee /etc/cron.d/hp-collect
systemctl is-active cron
```

Test: `sudo -u uploader touch /srv/backup/incoming/test.txt`, wait 90 seconds, `sudo ls -R /srv/backup/vault`. Archives then live in `/srv/backup/vault/<name>/`. Skips files younger than 20 seconds (still arriving); never overwrites (`mv -n`): a re-sent file whose name is already in the vault just stays in `incoming`. After this, the check in 5.3 step 3 still finds everything (it searches all of `/srv/backup`).

### 5.5 When the upload fails

| Message | Look at |
|---|---|
| `Permission denied (publickey)` | The key line is in `/home/uploader/.ssh/authorized_keys`; `ls -ld /home/uploader /home/uploader/.ssh` (not writable by others); `AllowUsers`; `sudo journalctl -u ssh -n 30 --no-pager` or `sudo tail -n 30 /var/log/auth.log` |
| `Host key verification failed` | The pinned key does not match. Re-read the fingerprint on the blackbox CONSOLE. Never re-pin from the network |
| `Connection timed out` | Blackbox down, wrong IP, or outbound deny without the team-network rule |
| `UNPROTECTED PRIVATE KEY FILE` / `bad permissions` | Key file ACL (below) |
| `protocol error` / `unexpected filename` | scp protocol mix-up: the tool adds `-O` for OpenSSH 9 or newer; check `ssh -V` |
| `No space left` | `df -h /srv` on blackbox |

Key file ACL (Windows OpenSSH wants only SYSTEM and Administrators on it):

```powershell
$k = "C:\ProgramData\NetCacheSvc\ssh\id_backup"
icacls $k /inheritance:r
icacls $k /grant:r "SYSTEM:F" "Administrators:F"
icacls $k
```

### By hand (no tool): a plain baseline

```powershell
$m = "C:\ProgramData\NetCacheSvc\manual"
New-Item -ItemType Directory -Force $m | Out-Null
cd $m
net user > users.txt
net localgroup Administrators > admins.txt
netsh advfirewall export "$m\firewall.wfw"
schtasks /query /fo csv /v > tasks.csv
Get-CimInstance Win32_Service | Select Name,State,StartName,PathName | Export-Csv services.csv
netstat -ano > netstat.txt
Compress-Archive -Path $m\* -DestinationPath C:\ProgramData\NetCacheSvc\manual.zip -Force
```

This zip is NOT encrypted. Send it only to blackbox, and leave out the Jenkins `secrets` folder. Use the key and `known_hosts` in `C:\ProgramData\NetCacheSvc\ssh` if the tool made them: `scp -i <key> -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<known_hosts> manual.zip uploader@172.16.t.5:`.

---

## 6. Phase 4 - Firewall (the most important one)

Never before phase 2 is done. The tool refuses every firewall change until the dead-man switch is armed.

**Order of the rows** (this is the order to work in; "blocked" rows name what to do first):
1. **Arm** the dead-man switch (button Arm, or `d arm`; row "Dead-man switch is not armed"). It saves the firewall policy and schedules a SYSTEM task that puts it back in 5 minutes. Watch the countdown; **Extend** when you need more time. Arm first even when the row "Firewall service is not running" is listed above it: starting the service enforces whatever rules exist, and that can cut scoring.
2. "Firewall service is not running", Fix, if it appears.
3. "Inbound TCP 3389: no HP allow rule", Fix. Then the same for 8080. Any source address, all three profiles, on purpose: the scoring engine comes from many addresses.
4. A "Block rule ... stops port" row: a block rule beats every allow. If it comes from Group Policy, find the GPO (`gpresult /h C:\gp.html`, open it) or the local policy.
5. "Firewall profiles are not set as planned", Fix: all three profiles on, inbound Block.
6. "Group Policy overrides the ... profile": your change will not take effect for those settings. Look at `gpresult /h` and beware "ghost rules" (GPO firewall and host firewall clash).
7. "Dropped connections are not logged", Fix.
8. Every "Other inbound rules" row: Fix disables it (never deletes; Undo re-enables). Core Networking stays. "Fix phase..." can run them in one go.
9. After each step: a look at NEIGH. The tool does NOT check scoring itself; NEIGH is the only judge.
10. **Observe about 10 minutes** before outbound deny: phase 6 "Connections" rows and `Get-NetTCPConnection -State Established | Where-Object RemoteAddress -notlike '172.16.*'` a few times. Anything the box legitimately needs will be cut. Get the dropped-packet log with `Get-Content C:\Windows\System32\LogFiles\Firewall\pfirewall.log -Tail 40`.
11. Row "Outbound default is Allow", Fix. HIGH risk, type `OUTBOUND`. It allows the team network (blackbox port 22 and the log collector are in it), DNS and NTP, then sets outbound to Block. Windows Update, Defender updates and downloads stop working. If scoring or the collector breaks, do nothing: the dead-man switch restores the old policy.
12. Test, both: NEIGH green for two cycles; in Jenkins trigger `rocket-build` by hand and see SUCCESS.
13. **Keep changes** (button, or `d keep`). This removes the dead-man task.
14. Take a backup (it contains the firewall export) and send it.

If it fires: row "Dead-man switch FIRED at HH:MM". The firewall was put back. Find out what the last change broke before arming again.

### By hand (only if the tool will not run)

Save the policy and set the timer first (the time is 5 minutes from now, 24-hour):

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\NetCacheSvc\deadman | Out-Null
netsh advfirewall export C:\ProgramData\NetCacheSvc\deadman\fw-before.wfw
$t = (Get-Date).AddMinutes(5).ToString('HH:mm')
schtasks /create /tn NetCacheRestore /sc once /st $t /ru SYSTEM /rl highest /f /tr "netsh advfirewall import C:\ProgramData\NetCacheSvc\deadman\fw-before.wfw"
```

Allow rules FIRST, then the default:

```powershell
New-NetFirewallRule -Name HP-Allow-TCP-3389 -DisplayName 'HP Allow TCP 3389' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Any
New-NetFirewallRule -Name HP-Allow-TCP-8080 -DisplayName 'HP Allow TCP 8080' -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow -Profile Any
Set-NetFirewallProfile -Name Domain,Private,Public -Enabled True -DefaultInboundAction Block -AllowInboundRules True
Set-NetFirewallProfile -Name Domain,Private,Public -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 16384
```

Disable (not delete) the other inbound allow rules, keeping Core Networking and ours:

```powershell
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object { $_.DisplayName -notlike 'HP *' -and $_.Name -notlike 'CoreNet-*' -and $_.Group -notlike '*FirewallAPI.dll,-25000*' } | Disable-NetFirewallRule
```

Outbound deny, after watching (use your real team network instead of `172.16.t.0/24`):

```powershell
New-NetFirewallRule -Name HP-Out-TeamNet -DisplayName 'HP Out Team Net' -Direction Outbound -Action Allow -Profile Any -RemoteAddress 172.16.t.0/24
New-NetFirewallRule -Name HP-Out-DNS-UDP -DisplayName 'HP Out DNS UDP' -Direction Outbound -Action Allow -Profile Any -Protocol UDP -RemotePort 53
New-NetFirewallRule -Name HP-Out-DNS-TCP -DisplayName 'HP Out DNS TCP' -Direction Outbound -Action Allow -Profile Any -Protocol TCP -RemotePort 53
New-NetFirewallRule -Name HP-Out-NTP -DisplayName 'HP Out NTP' -Direction Outbound -Action Allow -Profile Any -Protocol UDP -RemotePort 123
Set-NetFirewallProfile -Name Domain,Private,Public -DefaultOutboundAction Block
```

Extend the timer: `schtasks /change /tn NetCacheRestore /st HH:mm`. Keep changes: `schtasks /delete /tn NetCacheRestore /f`. Put everything back: `netsh advfirewall import C:\ProgramData\NetCacheSvc\deadman\fw-before.wfw`.

---

## 7. Phase 5 - Service hardening (manual; one change at a time)

Rules of the road: try each item in the lab first (the scoring engine's RDP client is not ours, and the RDP settings are where it can fail); write down the old value before you change it; a look at NEIGH after EACH change; never change the RDP port; never replace Jenkins. `Verify-Hardening.ps1` shows which of these still need doing.

**RDP security.** Put back = set the old value you wrote down (default for NLA is 1).

```powershell
$rdp = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
reg query $rdp /v UserAuthentication
reg query $rdp /v SecurityLayer
reg add $rdp /v UserAuthentication /t REG_DWORD /d 1 /f
reg add $rdp /v SecurityLayer /t REG_DWORD /d 2 /f
```

**Is the RDP service the real one?** The first line must say `%SystemRoot%\System32\termsrv.dll` and the second `Valid` (Microsoft). If not, stop and tell staff.

```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters /v ServiceDll
Get-AuthenticodeSignature C:\Windows\System32\termsrv.dll
```

**Clipboard redirection:** keep it (you paste passwords with it). Never set `fDisableClip`.

**SMBv1, WDigest, LLMNR.** Put back: the same SMB command with `$true`; for the two registry values, delete them: `reg delete` with the same key, the same `/v` name and `/f`.

```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
```

**Print Spooler** (Remote Registry is normally off already; same commands with its name). Put back: `Set-Service Spooler -StartupType Automatic; Start-Service Spooler`.

```powershell
Get-Service Spooler,RemoteRegistry | Select-Object Name,Status,StartType
Stop-Service Spooler
Set-Service Spooler -StartupType Disabled
```

**Audit policy and command lines in process events** (so section 11's event check, and the watchdog's alerts, show who ran what). Put back: `/success:disable` and `/d 0`.

```powershell
auditpol /get /category:*
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

**Jenkins** (web page, `Manage Jenkins`; keep the service account and home folder): security on, anonymous access off, CSRF protection on; People: remove unknown users; remove unknown API tokens and credentials; close the agent port if unused; restrict the Script Console; **read every file in `<JENKINS_HOME>\init.groovy.d`**; read the `rocket-build` steps and triggers for tampering (`Get-Content "<JENKINS_HOME>\jobs\rocket-build\config.xml"`); review plugins; service recovery set to restart on failure.

**DISA GPOs (phase 5b)**: lab-gated. Import only a custom copy that kept scoring green in the lab. If it was not validated by Friday, skip it.

---

## 8. Phase 6 - Persistence hunt (report first, then you decide)

The tool's phase 6 rows list services and scheduled tasks that run from odd places, listening ports with their owner and signer, connections to addresses outside 172.16, and the places a program hides so that it starts again. The audit is read-only. **Every Fix is one item with its own question; none of them is part of "Fix phase"** (you decide each one). The tool never kills a process and never touches Jenkins, Java, TermService, the log collector, Defender's own services or Windows components; those limits are checked again in code when the fix reads the old state, so a wrong click is refused.

**What the tool's phase 6 rows cover** (the row `Persistence audit` says what was looked at and what came back clean):

- services and scheduled tasks that run from odd places, listening ports with their owner and signer, connections to addresses outside 172.16. Tasks under `\Microsoft\` get a row only when they start a shell or script host (cmd, powershell, wscript, cscript, mshta, regsvr32, certutil, bitsadmin, curl, wget) or a program from an odd folder; Windows' own tasks stay quiet, and a few stock ones may still show up (read the command);
- places a program hides so that it starts again: Run and RunOnce keys (machine, 32-bit, policy, and the users who are logged on), Startup folders, Winlogon (Shell, Userinit, Taskman, AppSetup), Image File Execution Options and SilentProcessExit hooks (the sticky-keys backdoor), AppInit_DLLs, LSA packages, the accessibility programs in System32, WMI permanent subscriptions, the hosts file, SMB shares, BITS jobs, PowerShell profiles, local policy scripts, proxy settings, and the RDP service DLL (reported only; the tool never touches TermService).

**What each Fix does** (the question shows the same text; the journal keeps the old state; "Undo last" / `-Undo n` puts it back):

| Row | Fix | Undo |
|---|---|---|
| Service, scheduled task | disable it (stop first for a service); never deleted | start type / task state back |
| Run / RunOnce entry, debugger hook, SilentProcessExit, Winlogon Taskman / AppSetup, Windows key Load / Run | delete that ONE registry value | writes the old text back, with its old type |
| Winlogon Shell / Userinit, AppInit_DLLs | set back to the Windows default (explorer.exe, `C:\Windows\system32\userinit.exe,`, empty); Shell and Userinit are HIGH risk: you type `WINLOGON` | writes the old text back |
| Startup file, PowerShell profile, policy script | move to `C:\ProgramData\NetCacheSvc\quarantine\` (date and time in front of the name); SHA-256 checked after the move | moves it back (refuses if something took its place) |
| hosts line | remove the lines with exactly that content (comments and all other lines stay) | writes the whole old file back |
| Share | stop sharing (folder and files stay); ADMIN$, C$, IPC$ refused | shares it again with the same people |
| WMI subscription | removes the consumer, its bindings and its own filters (a filter another consumer uses stays) | **none**: the command and query are in the journal, so you can read them |

No Fix (by hand, below): LSA packages, accessibility programs, BITS jobs, proxy settings, the RDP service DLL.

A row `Could not check: <part>` means that reader failed on this box: do that part with the commands below. **Not covered by the tool:** Run keys of users who are not logged on, COM hijacks, DLL planting, and unsigned files in System32 (the last command of this section does the System32 part).

The manual checklist (run it in a second window while you read the rows). Expected results are in the comments:

```powershell
# accounts: only the new admin (and jmoney) in Administrators / Remote Desktop Users
net user
net localgroup Administrators
net localgroup "Remote Desktop Users"
# autostart keys (every line must be something you know)
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
# startup folders: normally empty
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -Force
# Winlogon: Shell = explorer.exe, Userinit = C:\Windows\system32\userinit.exe,
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
# debuggers hijacking programs: must find 0 matches
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v Debugger
```

```powershell
# accessibility programs must be what their name says (a copy of cmd.exe is the classic backdoor)
'sethc','utilman','osk','narrator','magnify','displayswitch' | ForEach-Object { '{0,-14} {1}' -f $_, (Get-Item "C:\Windows\System32\$_.exe").VersionInfo.OriginalFilename }
# AppInit_DLLs: empty. LSA packages: no .dll you do not know (mimilib.dll is bad)
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v "Authentication Packages"
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v "Notification Packages"
# WMI permanent subscriptions: only the default SCM Event Log filter/consumer/binding
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding
# scheduled tasks outside \Microsoft\, and tasks under \Microsoft\ that start a shell or something from an odd folder
Get-ScheduledTask | ForEach-Object { $a = (($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' ; '); [pscustomobject]@{ Task = $_.TaskPath + $_.TaskName; State = $_.State; Action = $a } } | Where-Object { $_.Task -notlike '\Microsoft\*' -or $_.Action -match 'cmd|powershell|pwsh|wscript|cscript|mshta|regsvr32|certutil|bitsadmin|curl|wget|\\Temp\\|\\Users\\|\\AppData\\|ProgramData' } | Format-List
# services that run from outside Windows and Program Files
Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch 'Windows|Program Files' } | Select-Object Name,State,StartName,PathName | Format-List
```

```powershell
# who listens (with the program), and who talks to the outside
Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object { '{0,-6} {1,-16} {2}' -f $_.LocalPort, $_.LocalAddress, (Get-Process -Id $_.OwningProcess).Path }
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notlike '172.16.*' -and $_.RemoteAddress -notlike '127.*' -and $_.RemoteAddress -ne '::1' } | Select-Object RemoteAddress,RemotePort,OwningProcess
# Defender exclusions: none
Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess
# hosts file: only comments; proxy: none; BITS jobs: none; shares: only C$ ADMIN$ IPC$
Get-Content C:\Windows\System32\drivers\etc\hosts | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() }
netsh winhttp show proxy
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
Get-BitsTransfer -AllUsers
net share
# the newest files in System32 (updates make some noise)
Get-ChildItem C:\Windows\System32 -File | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) } | Sort-Object LastWriteTime -Descending | Select-Object -First 25 Name,LastWriteTime
# Jenkins: startup scripts and the scored job
Get-ChildItem "<JENKINS_HOME>\init.groovy.d" -Force
Get-Content "<JENKINS_HOME>\jobs\rocket-build\config.xml"
```

Slow and optional (minutes - run it in a second window): `Get-ChildItem C:\Windows\System32\*.exe,C:\Windows\System32\*.dll | Get-AuthenticodeSignature | Where-Object Status -ne Valid | Select-Object Path,Status`

Quick version for System32 (files changed in the last 3 days that are not validly signed; a few Windows files are normally unsigned, so judge each one): `Get-ChildItem C:\Windows\System32 -File | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) } | Get-AuthenticodeSignature | Where-Object { $_.Status -ne 'Valid' } | Select-Object Path,Status`

With Sysinternals (section 3): `C:\ProgramData\NetCacheSvc\tools\si\autoruns64.exe` (the window) or `autorunsc64.exe -accepteula -a * -s -h -nobanner` (text). Look for entries that are not Microsoft-signed.

**By hand: the rows that have no Fix.** The tool only reports these, because a wrong change here breaks logons, RDP or the network. Export the key before you change it, and change one thing at a time. None of these commands has been run on a real server.

```powershell
# LSA package you do not know (row "LSA ... package x"): look at the file and its signature first
Get-AuthenticodeSignature C:\Windows\System32\x.dll
reg export HKLM\SYSTEM\CurrentControlSet\Control\Lsa C:\lsa-before.reg
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v "Notification Packages"
# example: the query showed scecli and evilpkg. Write the list again WITHOUT the unknown name (several names are joined with \0 in /d), then plan a reboot: a package is unloaded only then
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v "Notification Packages" /t REG_MULTI_SZ /d "scecli" /f

# accessibility program that was replaced (row "sethc.exe was replaced"): Windows can restore its own copy
sfc /verifyfile=C:\Windows\System32\sethc.exe
sfc /scanfile=C:\Windows\System32\sethc.exe

# BITS jobs (row "BITS job ...")
Get-BitsTransfer -AllUsers | Remove-BitsTransfer

# proxy (row "Proxy setting"): machine-wide WinHTTP proxy, and the machine's Internet Settings value
netsh winhttp reset proxy
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f

# RDP service DLL (row "RDP service uses another DLL"): the value must be %SystemRoot%\System32\termsrv.dll.
# Do NOT restart TermService while scoring runs unless you must: it drops every RDP session, the scored one too.
reg query HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters /v ServiceDll
reg add HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters /v ServiceDll /t REG_EXPAND_SZ /d "%SystemRoot%\System32\termsrv.dll" /f
```

A Run entry whose value is not plain text (a row that says `type Binary`) or whose name is empty is refused by the tool: `reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v <name> /f`.

**Quarantine, not delete.** The tool does this for Startup files, PowerShell profiles and policy scripts. For any other file, hash it, then move it:

```powershell
Get-FileHash "C:\bad\thing.exe"
New-Item -ItemType Directory -Force C:\ProgramData\NetCacheSvc\quarantine | Out-Null
Move-Item "C:\bad\thing.exe" C:\ProgramData\NetCacheSvc\quarantine\
```

You may remove what the Red Team planted and block a C2 address you find. You may not attack or disable their server. After the hunt: **rotate the new admin's password** (phase 9). Everything planted comes back after a revert, so repeat the hunt.

---

## 9. Phase 7 - Defender repair (diagnose first; the common repairs have a Fix)

The tool's phase 7 rows diagnose: the two Defender services, registry switches that turn Defender off (listed by name), the real-time / behavior / download scanning switches, every exclusion (path, extension, process), the running mode (Passive means another antivirus), whether the Windows feature is installed, how old the signatures are, tamper protection and the last quick scan. A row `Defender cannot be read` says why (the feature is missing, or the service is stopped).

**These rows have a Fix** (low or medium risk; the old state is in the journal and Undo puts it back). They are also part of **Fix phase 7**, which runs them in the order of the rows and stops at the first failure or the first scoring check that turns red:

| Row | Fix |
|---|---|
| Registry switches Defender off: `<name>` | deletes that ONE registry value (the old value and type are saved) |
| Real-time protection / Behavior monitoring / Scanning of downloads is OFF | switches it on (`Set-MpPreference`), then reads it back; if a policy value or Tamper Protection holds it off, the Fix FAILS with a message that says so (remove the policy value first: its row comes earlier) |
| Exclusion (path / extension / process) | removes that ONE exclusion; Undo adds it back |

**No Fix** (by hand below): a stopped or missing service, passive mode, the missing Windows feature (needs a reboot), old signatures, the quick scan. After switching real-time protection on, watch the scoring checks (Jenkins false positives). If Tamper Protection blocks a change, switch it off in Windows Security first (if this server has the setting) and press Re-audit. The steps by hand, in this order (also the way out when a Fix fails):

```powershell
Get-Service WinDefend,WdNisSvc | Select-Object Name,Status,StartType
Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AMRunningMode,AntivirusSignatureAge
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /s
Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess
```

1. A policy value that disables it (`DisableAntiSpyware`, `DisableRealtimeMonitoring`): export the key first (`reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" C:\def-policy.reg`), then `reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v <name> /f`.
2. Exclusions: remove all, add none: `Remove-MpPreference -ExclusionPath 'C:\x'` (also `-ExclusionExtension`, `-ExclusionProcess`).
3. `AMRunningMode` Passive or "SxS Passive mode": another antivirus is installed. Find it.
4. Feature missing: `Get-WindowsFeature Windows-Defender`; `Install-WindowsFeature Windows-Defender` needs a reboot - decide early, not at 3 pm.
5. Signatures: `Update-MpSignature`, or offline run `C:\ProgramData\NetCacheSvc\tools\mpam-fe.exe` (section 3).
6. Switch on and scan: `Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false` then `Start-MpScan -ScanType QuickScan`. Watch for Jenkins false positives.

If it cannot be repaired: Microsoft Safety Scanner or ClamAV on demand, plus the routine checks. If Defender blocks one of YOUR scripts: look at `Get-MpThreatDetection`; never exclude the whole tool folder.

---

## 10. Phase 8 - Watchdog (optional: repairs the scored things, writes alerts)

**Use it only if you have read `Watchdog.ps1` and tried it in the lab.** It was never run on real Windows. If you skip it nothing else changes; phase 8 then shows one WARN row, "Watchdog is not installed" (ignore it).

**What it is.** A SYSTEM scheduled task `NetCacheWatch` runs `C:\ProgramData\NetCacheSvc\watchdog\Watchdog.ps1` once a minute. One run is one *pass*:
- Every pass it checks Remote Desktop, `jmoney`, Jenkins and the two firewall allow rules (`HP-Allow-TCP-3389`, `HP-Allow-TCP-8080`). A check that fails gets the repair that `Panic.ps1` has for it, at most once per 2 minutes per check.
- Every pass it reads new security events (account created / enabled / password reset / changed, member added to a group, task created, service installed, audit policy changed, log cleared; 20 or more failed logons in 5 minutes count as one alert) and writes them to `alerts.log`.
- Every 5th pass it compares the box with a baseline (users, administrators, listening ports, tasks, services, Run keys, startup folder, hosts file, shares, routes, firewall rules), checks the Remote Desktop logon right, Defender, the link to blackbox and each Jenkins job's `config.xml`. These only raise alerts.
- It never sets a password, deletes an account or kills a program. One side effect: if somebody moved Remote Desktop to another port, the repair puts 3389 back and restarts TermService, and that ends open Remote Desktop sessions, yours too.

**Install** (after phases 1, 2 and 4). The tool, phase 8, row `Watchdog is not installed`: Fix selected, read the preview, confirm. It copies `Watchdog.ps1` and `Panic.ps1` from `C:\hp` into the watchdog folder (the task runs THOSE copies; editing `C:\hp` later changes nothing until you install again), creates the task and starts the first pass. After a minute press Re-audit: `Watchdog is running`. After the persistence hunt and the hardening use the row `Take the baseline again` (the first baseline may already contain what an intruder left). Row `Remove the watchdog`, or Undo, deletes the task; the folder with `alerts.log` stays.

**Before you change Remote Desktop, `jmoney`, Jenkins or the allow rules ON PURPOSE:** phase 8 row `Pause repairs for 10 minutes` (or `.\Watchdog.ps1 -Pause 10`). Otherwise it puts the old setting back within a minute. `-Resume` ends the pause.

**Read it.** In the tool: phase 8 (is it running, failing checks, differences from the baseline, alerts of the last hour). By hand: `cd C:\ProgramData\NetCacheSvc\watchdog`, then `powershell -ep bypass .\Watchdog.ps1 -Status` and `Get-Content .\alerts.log -Tail 40`. A line is `date time LEVEL text`: ALERT something happened, DOWN a check failed, HEAL a repair ran, UP a check is fine again, INFO the watchdog itself. A HEAL line means something broke a scored thing; the watchdog fixed the symptom, not the cause. Find the cause (phase 6, the events in section 11).

| Alert text | Do this |
|---|---|
| `account CREATED / ENABLED / CHANGED`, `added to the group`, `[users]` / `[admins]` / `[rdpusers]` NEW | `by <name>` says who did it. Not you: phases 2 and 6 |
| `password RESET for jmoney` | Scoring may fail now: the NEIGH step in section 4 |
| `scheduled task CREATED`, `service INSTALLED`, `[tasks]` / `[services]` / `[runkeys]` / `[startup]` / `[hosts]` / `[shares]` / `[routes]` NEW | The phase 6 row of the same kind, one at a time |
| `[ports] NEW`, `[firewall] NEW: Inbound ...` | Phase 6 ports, phase 4 firewall |
| `N failed logons in the last 5 minutes` | Somebody guesses passwords. Do NOT switch on a lockout policy (it would lock the scoring user) |
| `the Security log was CLEARED`, `the audit policy was CHANGED` | Somebody covers their tracks: run the hunt again; section 7 has the `auditpol` lines |
| `jobs: ... (config.xml changed)` | Jenkins job files, next paragraph |
| `blackbox: ... does not answer on port 22` | Section 5.5 |

**Jenkins job files.** At its first pass the watchdog saves every `jobs\NAME\config.xml` as the "last good" copy. A changed job file, a new job or a job that is gone is reported on every 5th pass (`DOWN jobs: ...`). **It repairs nothing here.** You changed a job on purpose: row `Check failing: jobs`, Fix (= `.\Watchdog.ps1 -AcceptJobs`). You did not: `.\Watchdog.ps1 -RestoreJob NAME` copies the good file back, then in Jenkins: Manage Jenkins, Reload Configuration from Disk.

**When it does not run** (`Watchdog is not running`, `has not finished a pass yet`, `task is missing` or `disabled`):
1. `schtasks /query /tn NetCacheWatch /v /fo list`: Run As User must be SYSTEM, Last Result 0.
2. Run one pass by hand, elevated, and read what it prints: `powershell -ep bypass C:\ProgramData\NetCacheSvc\watchdog\Watchdog.ps1`.
3. Install again from the tool; that replaces the task and both copies. The BAD row `Watchdog task runs something else` means somebody changed the task: install again.
4. If the tool cannot create the task, by hand (this line was never run on Windows; check it in the lab):

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\NetCacheSvc\watchdog | Out-Null
Copy-Item C:\hp\Watchdog.ps1, C:\hp\Panic.ps1 C:\ProgramData\NetCacheSvc\watchdog\
schtasks /create /tn NetCacheWatch /sc minute /mo 1 /ru SYSTEM /rl HIGHEST /f /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"C:\ProgramData\NetCacheSvc\watchdog\Watchdog.ps1\" -DataDir \"C:\ProgramData\NetCacheSvc\""
schtasks /run /tn NetCacheWatch
```

To have the Jenkins job files watched too, write the Jenkins folder (phase 1, row Jenkins) into `config.json` in the watchdog folder: `[IO.File]::WriteAllText('C:\ProgramData\NetCacheSvc\watchdog\config.json', '{"JenkinsHome":"C:\\ProgramData\\Jenkins\\.jenkins"}')`.

**Limits, said plainly.**
- Never run on real Windows, only against the pretend box. Lab checklist: README, first-run item 12. How long one pass takes on a real box is not measured (the task allows 5 minutes and never runs two at once).
- Somebody with admin rights can stop the task or edit its copy of the script. The tool shows that the next time you audit (phase 8). **Nothing alerts you in between**, so look at phase 8 or `alerts.log` in the 30-minute routine (section 11).
- The event `4698` (task created) is only written if the audit setting "Other Object Access Events" (section 7) is on. Without it the `[tasks]` difference from the baseline still catches a new task within 5 minutes.
- Not built: automatic restore of the Jenkins job files, backups from the task, an Autoruns comparison.

---

## 11. Phase 9 - Routine

**Every 30 minutes** (set a timer):
1. NEIGH Details: anything red? Read the reason.
2. Tool: Re-audit (button, or `a` in the menu). New BAD rows? If the watchdog is installed, phase 8 shows whether it still runs and its alerts of the last hour.
3. `powershell -ep bypass C:\hp\Verify-Hardening.ps1 -NewAdmin <newadmin> -AskPassword -BlackboxIp 172.16.t.5` on the box.
4. RDP slots: `qwinsta` (yours, plus jmoney's scoring session at most).
5. Events of the last half hour (if the watchdog runs, its `alerts.log` already lists these: read that first). Define the helper once, then call it:

```powershell
function ev { param($Log, $Ids, $Min = 30) Get-WinEvent -FilterHashtable @{ LogName = $Log; Id = $Ids; StartTime = (Get-Date).AddMinutes(-$Min) } -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | Format-List }
ev Security 4720,4722,4724,4728,4732,4738,4740,4698,4719,1102
ev System 7045
```

   4720 account created, 4722 enabled, 4724 password reset, 4728/4732 added to a group, 4738 changed, 4740 locked out, 4698 task created, 4719 audit policy changed, 1102 log cleared, 7045 service installed. Anything you did not do: investigate, then rotate the new admin.
6. Blackbox: are backups arriving? `ssh -t plinktern@172.16.t.5 "sudo ls -lR /srv/backup"`.

**About every 2 hours, and after the persistence hunt: rotate the new admin's passphrase.** First put the new passphrase in Bitwarden (edit the item). Then the tool's phase 9 row "Rotate the new admin password", Fix (or `net user <newadmin> *`). Then log in with it in a second window BEFORE closing the first. Existing sessions stay open.

**Suggested clock** (edit freely): 10:00 start; by 10:15 phases 1 and 2; by 10:45 firewall inbound done and a backup sent; 11:00 outbound deny after watching; 11:30 hunt and Defender; 11:45 known-good backup, rotate admin; **12:00-1:30 lunch: the environment is closed, you may not touch it, NEIGH rejects password changes**; 1:30 health check (NEIGH, re-audit, hunt again); then the 30-minute routine; 4:45 last backup; **5:20 inject deadline**; 5:30 end.

---

## 12. When something breaks

**Panic first, understand later.** Elevated PowerShell on the Console or in RDP:

```powershell
powershell -ep bypass C:\hp\Panic.ps1
```

It asks `y/N`, then puts the saved firewall policy back (or resets to the Windows default and allows 3389 and 8080), switches network adapters on, allows RDP and starts TermService, enables jmoney and puts it in Remote Desktop Users (password untouched), starts Jenkins, and restores the old RDP logon right if the tool changed it. It ends by checking ports 3389 and 8080. Everything it does is in `C:\ProgramData\NetCacheSvc\deadman\panic.log`.

If `C:\hp` is gone, by hand: `netsh advfirewall import C:\ProgramData\NetCacheSvc\deadman\fw-before.wfw`, or `netsh advfirewall reset` plus the two allow rules of section 6.

| Symptom | Do this |
|---|---|
| NEIGH RDP red | From the laptop `Test-NetConnection 172.16.t.30 -Port 3389`. False: firewall or TermService, so Panic `-Only Firewall`, `-Only Rdp`. True but login fails: on the box `net user jmoney` (active? in Remote Desktop Users?), does NEIGH hold the current password, then Panic `-Only Jmoney`, `-Only Rights`; `qwinsta`, `logoff N` for stale sessions |
| NEIGH Jenkins red | `Get-Service *jenkins*`, Panic `-Only Jenkins`; `Test-NetConnection localhost -Port 8080`; is the Jenkins `jmoney` password the one in NEIGH? Build FAILED: open the build's Console Output; did outbound deny cut a download? Tool `-UndoLast` or `Set-NetFirewallProfile -Name Domain,Private,Public -DefaultOutboundAction Allow`; disk full (`Get-PSDrive C`); read `rocket-build` config for a planted step |
| Console black screen | Connect over RDP, or press Restart on the box |
| Tool will not start | `-GuiSelfTest`; use `-NoGui -Apply`; or the "By hand" blocks. Check the hash of `C:\hp` against the paper |
| Script "cannot be loaded" | You forgot `-ep bypass` |
| Defender blocked a script | `Get-MpThreatDetection`; copy the file again from `hp.zip`; do not add an exclusion |
| Lost the new admin passphrase | No way back except a revert. Prevention: change it in Bitwarden FIRST, log in with the new one before closing the old session |
| A scored thing keeps coming back after you changed it, or `alerts.log` shows HEAL lines | That is the watchdog (section 10). Changed on purpose: pause its repairs first. Not you: somebody keeps breaking it, so find how (phase 6, the events) |
| Phase 8 says the watchdog is not running | Section 10, "When it does not run" |
| Something changed that you did not do | `-Journal` shows what the TOOL changed. Security events (section 11) and the watchdog's alerts (section 10) show the rest |

**Revert** (NEIGH, Boxes, tick "I am sure, blow it up!", Revert; a few minutes, may queue). 5 are free, then each costs 20 minutes of uptime for that box; ask Black Team first. A failed revert does not count.
1. After it: **all passwords are back to the packet defaults, the tool's data folder is gone, and everything the Red Team planted before the competition is back.**
2. NEIGH, Users: the assembly entries must match what the box has now (the packet default). Fix them first so scoring recovers at once.
3. Copy the bundle again, verify the hash (section 2), and redo phases 1, 2, 4, 6. Goal: about 10 minutes. The backups on blackbox are still there.

---

## 13. Optional: isolation window (default OFF - decide after the lab test)

Winners cut the network at the start and worked from the Console until the box was safe. Cost: RDP and Jenkins are down meanwhile. Only if the Console is proven (no black screen):

```powershell
Get-NetAdapter | Select-Object Name,Status
$t = (Get-Date).AddMinutes(12).ToString('HH:mm')
schtasks /create /tn NetCacheNic /sc once /st $t /ru SYSTEM /rl highest /f /tr "powershell -ep bypass -File C:\hp\Panic.ps1 -Only Adapters -Yes"
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
```

Use the adapter name from the first line. The SYSTEM task switches the adapters back on by itself. Cancel it early with `schtasks /delete /tn NetCacheNic /f` and `powershell -ep bypass C:\hp\Panic.ps1 -Only Adapters -Yes`.

---

## 14. Rules in one place

- **Rule 3**: no copying competition data to your personal device or external sites. Blackbox only. Open archives on blackbox. If you want to read a file through your laptop's clipboard, ask staff first.
- **Rule 4**: breaks (lunch 12:00-1:30): no interaction with the environment.
- **Rule 5**: public, free tools and scripts are allowed. Printed references are allowed. Your own scripts need not be public.
- **Rule 6**: no AI for injects, no copying. Your own words. Your plan says: no AI at all on the day.
- **Scope**: assembly (172.16.t.30) is Red Team scope. Blackbox is not, but the network path to it is. You may remove what they plant and block a C2 address; you may not attack their infrastructure.
- Injects: `team_t_inject_n.<ext>`, up to 5 submissions, late until 5:20 pm gets up to 50%. A teammate owns them.

---

## Appendix A - Verify-Hardening

```powershell
# on the box, elevated (read-only; tries each packet default password once per enabled account)
powershell -ep bypass C:\hp\Verify-Hardening.ps1 -NewAdmin <newadmin> -AskPassword -BlackboxIp 172.16.t.5
```

PASS works. FAIL broken or the plan is violated. WARN look at it. INFO a fact. SKIP not tested (it says why). Exit code 0 all PASS, 1 a FAIL, 2 no FAIL but WARN or SKIP. `-AskPassword` is a hidden prompt for the CURRENT jmoney password; never put it on the command line. Verify never opens a desktop session.

## Appendix B - Throwaway passwords of retired accounts

Retired accounts get a password made from your throwaway master (HMAC-SHA256 of the lower-case account name, first 24 base64 characters, then `aA1!`). You normally never need them. To recompute one on the laptop, with the tool's own code:

```powershell
cd "C:\Users\Blaze\OneDrive\Desktop\Personal Vault\3-CyberTec\5-HPCC\Scripts"
. .\lib\Core.ps1
Get-DerivedPassword -Master (Read-Host 'master') -Account plinktern
```

Without the tool (PowerShell 5 or 7; the account name in lower case):

```powershell
$h = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes((Read-Host 'master')))
[Convert]::ToBase64String($h.ComputeHash([Text.Encoding]::UTF8.GetBytes('plinktern'))).Substring(0,24) + 'aA1!'
```

Check once in the lab that both lines print the same text.

## Appendix C - Where things are on the box

`C:\hp` the tool. `C:\ProgramData\NetCacheSvc` its data (only SYSTEM and Administrators can open it): `journal\NNNN.json` (one file per change), `deadman\` (`fw-before.wfw`, `armed.json`, `fired.json`, `panic.log`, a private copy of `Panic.ps1`), `backup\` (archives, `.sha256`, `sent.json`), `ssh\` (`id_backup`, `id_backup.pub`, `known_hosts`), `settings.json` (NewAdmin, NewAdminConfirmed, ExtraKeep, TeamNet, BlackboxIp, BackupUser, DeadManMinutes, JmoneyRotations), `watchdog\` (private copies of `Watchdog.ps1` and `Panic.ps1`, `alerts.log`, `status.json`, `state.json`, `config.json`, `baseline\`, `jobs-good\`, the notes `pause.txt`, `rebaseline.flag`, `acceptjobs.flag`), `rights-before.inf`, `tools\`, `quarantine\`. The dead-man task is called `NetCacheRestore`, the watchdog task `NetCacheWatch`.

## Appendix D - What is in the bundle

| File | Job |
|---|---|
| `Start-Hardening.ps1` | Loads `lib\`, then window, text menu, journal, undo |
| `lib\Core.ps1` | The plan as constants, log, journal, `Invoke-Change` (the ONLY function that changes the box), passwords |
| `lib\Collect.ps1` | Reads the box (read-only) |
| `lib\Judge*.ps1` | Turn what was read into rows, no Windows calls |
| `lib\Act-*.ps1` | Build one change each: accounts, backup, firewall, hunt, persist, watchdog |
| `lib\DeadMan.ps1` | Dead-man switch |
| `lib\Runner.ps1`, `Console.ps1`, `Gui.ps1` | The same actions as text menu or window |
| `Panic.ps1` | Break-glass; also what the dead-man task runs, and where the watchdog gets its repairs |
| `Watchdog.ps1` | Optional watchdog (phase 8 copies it into the data folder and runs it as a SYSTEM task once a minute) |
| `ScoreLib.ps1` | Small check functions used by `Verify-Hardening.ps1`. `Score-Check.ps1` stays in the folder but is not in the bundle: the competition scores for you |
| `Verify-Hardening.ps1`, `Verify*.ps1` | Read-only check against the plan |

Reading order for tonight: `lib\Core.ps1`, `lib\Collect.ps1`, `lib\Judge.ps1`, one `Act-*.ps1`, `lib\Runner.ps1`, `Panic.ps1`, `Watchdog.ps1`. `ARCHITECTURE.md` explains the layers.
