# Citadel Test Samples

This directory contains comprehensive test samples for all log types supported by Citadel.

## Quick Start

Upload the `all_text_logs_samples.zip` file to a Citadel case to test all text-based log parsers.

## Generated Test Files

### Network Security Logs (Already Existed)

| File | Format | Description |
|------|--------|-------------|
| `auth.log` | Syslog | Linux authentication logs (SSH, sudo, kernel) |
| `conn.log` | Zeek | Network connection logs |
| `eve.json` | Suricata | IDS/IPS alerts in JSON format |
| `forensic_events.jsonl` | NDJSON | Generic forensic events |

### Web Server Logs (NEW)

| File | Format | Description |
|------|--------|-------------|
| `access.log` | Apache Combined | HTTP access logs with referer and user agent |
| `access_common.log` | Apache Common | HTTP access logs (basic format) |
| `error.log` | Nginx Error | Web server error logs |

### Shell History (NEW)

| File | Format | Description |
|------|--------|-------------|
| `.bash_history` | Bash | Bash command history with timestamps |
| `.zsh_history` | Zsh | Zsh extended history format |
| `fish_history` | Fish | Fish shell YAML-like history |
| `CONSOLEHOST_HISTORY.TXT` | PowerShell | PowerShell console history |

### macOS Unified Logging (NEW)

| File | Format | Description |
|------|--------|-------------|
| `unified.log` | ULS Text | macOS unified log text export |
| `unified.ndjson` | ULS NDJSON | macOS unified log JSON format |

### Windows Artifacts (NEW)

| File | Format | Description |
|------|--------|-------------|
| `chrome.exe.wer` | WER XML | Windows Error Reporting crash dump |
| `malicious_task.xml` | Task Scheduler | Exported scheduled task XML |
| `CorporateWiFi.xml` | WLAN Profile | Exported WiFi profile with credentials |
| `registry_export.reg` | Registry Export | Windows registry .reg file |

### macOS Artifacts (NEW)

| File | Format | Description |
|------|--------|-------------|
| `com.malicious.persist.plist` | Plist XML | macOS LaunchAgent persistence |

### Linux Configuration (NEW)

| File | Format | Description |
|------|--------|-------------|
| `sshd_config` | Config | SSH daemon configuration |
| `crontab` | Crontab | Scheduled tasks with suspicious entries |
| `fstab` | Config | Filesystem mount configuration |

### Filesystem Artifacts (NEW)

| File | Format | Description |
|------|--------|-------------|
| `MFT.csv` | MFT CSV | NTFS Master File Table export |

### JSON Files (NEW)

| File | Format | Description |
|------|--------|-------------|
| `forensic_events.json` | JSON | Structured forensic events |

### Strings Fallback Test Files (NEW)

| File | Format | Description |
|------|--------|-------------|
| `fake.exe` | PE Binary | Fake executable for strings extraction |
| `suspicious.sh` | Shell Script | Script for strings extraction test |

### Browser Artifacts (Already Existed)

| File | Format | Description |
|------|--------|-------------|
| `History` | SQLite | Chromium browser history database |

## Complete List of Citadel Supported Log Types

Citadel supports **25+ log types** through its plugin architecture:

### Text-Based Logs (Covered in this test set)
1. ✅ Syslog
2. ✅ Zeek (conn.log, dns.log, http.log, etc.)
3. ✅ Suricata (eve.json)
4. ✅ NDJSON/JSONL
5. ✅ Access logs (Apache/Nginx)
6. ✅ Shell history (bash, zsh, fish, PowerShell)
7. ✅ macOS ULS (Unified Logging System)
8. ✅ WER (Windows Error Reporting)
9. ✅ Plist (macOS property lists)
10. ✅ Scheduled tasks (XML)
11. ✅ WLAN profiles
12. ✅ Linux config files
13. ✅ MFT (CSV export)
14. ✅ Registry exports (.reg)
15. ✅ JSON files
16. ✅ Strings fallback

### Binary Formats (Not covered - require specialized tools)
17. ⬜ EVTX (Windows Event Logs) - requires python-evtx
18. ⬜ Prefetch (.pf) - requires pyscca
19. ⬜ LNK shortcuts - requires LnkParse3
20. ⬜ Registry hives - requires python-registry
21. ⬜ MFT (raw $MFT) - requires mft or analyzeMFT.py
22. ⬜ Plaso timelines - requires plaso
23. ⬜ PCAP/PCAPNG - requires tshark/pyshark
24. ⬜ Disk images (DD, E01) - requires pytsk3
25. ⬜ Android artifacts - requires specific parsers
26. ⬜ iOS artifacts - requires specific parsers
27. ⬜ Archive files (ZIP, 7z, RAR) - requires extraction

## Testing Instructions

1. **Upload individual files**: Upload any file to a Citadel case to test the specific parser
2. **Upload the complete zip**: Upload `all_text_logs_samples.zip` to test all text-based parsers at once
3. **Check the timeline**: Verify events appear with correct timestamps and artifact types
4. **Review parsing stats**: Check plugin statistics for parsing success rates

## Expected Artifact Types

When parsed correctly, files should produce events with these artifact_type values:

- `access_log` - Web server access logs
- `shell_history` - Command history
- `macos_uls` - macOS unified logs
- `process` - WER crash reports
- `registry` - Registry exports
- `persistence` - Scheduled tasks, launch agents
- `mft` - Filesystem metadata
- `timeline` - Generic timeline events
- `binary_file` - Strings fallback results

## File Naming Conventions

Citadel uses filename and content detection to route files to the correct parser:

- Files starting with `.` (like `.bash_history`) are detected by name
- Files with specific extensions (`.log`, `.xml`, `.plist`) are detected by extension and content
- Generic files (`.json`, `.txt`) are detected by content inspection

## Contributing

To add more test samples:
1. Create realistic log entries with forensic-relevant events
2. Include both benign and suspicious activity patterns
3. Ensure timestamps are in correct format for the log type
4. Add the file to this directory and update this README

## License

These test files are provided for testing and educational purposes.
