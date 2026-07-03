/**
 * Collector page — artifact collection script wizard.
 *
 * Generates a pre-configured Python script for live systems,
 * mounted directories (--path), or external drives (--disk).
 * Server-side harvest is available inside the ingestion panel of each case.
 */
import { useState, useEffect, useRef, useMemo } from 'react'
import {
  Monitor, Terminal, FileCode, Download, Check,
  ChevronRight, ChevronLeft, X,
  AlertTriangle, Upload, Copy, FolderOpen,
} from 'lucide-react'
import { api } from '../api/client'
import ArtifactSelector from '../components/shared/ArtifactSelector'

function _currentUser() {
  try { return JSON.parse(localStorage.getItem('fo_user')) } catch { return null }
}

// ── Artifact definitions (script mode) ───────────────────────────────────────

const WINDOWS_ARTIFACTS = [
  // ── Core ────────────────────────────────────────────────────────────────────
  { key: 'evtx',              label: 'Event Logs (EVTX)',               desc: 'Security, System, Application, PowerShell, Sysmon and more' },
  { key: 'registry',          label: 'Registry Hives',                  desc: 'SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat' },
  { key: 'prefetch',          label: 'Prefetch Files',                  desc: 'Program execution evidence (up to 500 .pf files)' },
  { key: 'mft',               label: 'Master File Table ($MFT)',        desc: 'Raw NTFS MFT — requires Administrator or dead-box access' },
  { key: 'execution',         label: 'Execution Evidence',              desc: 'SRUM database, Amcache.hve, Prefetch — comprehensive execution history' },
  { key: 'persistence',       label: 'Persistence (Tasks + WMI)',       desc: 'Scheduled Tasks XML from System32/SysWOW64, WMI repository (OBJECTS.DATA)' },
  { key: 'filesystem',        label: 'NTFS Metadata',                   desc: '$MFT, $LogFile, $Boot — full NTFS journal and boot sector' },
  // ── Network & USB ────────────────────────────────────────────────────────────
  { key: 'network_cfg',       label: 'Network Config',                  desc: 'Hosts file, WLAN profiles (.xml), Windows Firewall logs (pfirewall.log)' },
  { key: 'usb_devices',       label: 'USB Device History',              desc: 'setupapi.dev.log / setupapi.setup.log — device plug-in timeline' },
  // ── Credentials & Security ───────────────────────────────────────────────────
  { key: 'credentials',       label: 'Credentials (DPAPI)',             desc: 'SAM, SECURITY hives, Credential Manager stores, DPAPI Protect folders' },
  { key: 'antivirus',         label: 'Antivirus / EDR',                 desc: 'Defender + Trend Micro, Symantec, McAfee/Trellix, Sophos, ESET, Kaspersky, Bitdefender, CrowdStrike, SentinelOne, Carbon Black and more — logs, quarantine, detections' },
  { key: 'sysmon',            label: 'Sysmon',                          desc: 'Sysmon Operational EVTX, config XMLs, FileDelete archive, SysmonDrv driver rules + service state (live)' },
  { key: 'wer_crashes',       label: 'WER Crash Dumps',                 desc: 'Windows Error Reporting crash dumps and report archives' },
  { key: 'win_logs',          label: 'Windows Logs',                    desc: 'CBS.log, DISM, WindowsUpdate.log, Panther setup logs' },
  { key: 'boot_uefi',         label: 'Boot Config (BCD / EFI)',         desc: 'BCD store, bootstat.dat — boot persistence indicators' },
  { key: 'encryption',        label: 'Encryption Metadata',             desc: 'BitLocker FVE recovery info, EFS metadata' },
  { key: 'etw_diagnostics',   label: 'ETW Diagnostic Traces',           desc: 'Windows/System32/LogFiles/WMI — .etl trace files' },
  // ── Browsers ─────────────────────────────────────────────────────────────────
  { key: 'browser',           label: 'All Browsers',                    desc: 'Chrome, Edge, Firefox, Brave, Opera, Vivaldi — history, cookies, logins' },
  { key: 'browser_chrome',    label: 'Chrome',                          desc: 'History, Cookies, Login Data, Bookmarks, Web Data for all users' },
  { key: 'browser_edge',      label: 'Microsoft Edge',                  desc: 'History, Cookies, Login Data, Web Data for all users' },
  { key: 'browser_ie',        label: 'Internet Explorer',               desc: 'WebCacheV01.dat / WebCacheV24.dat — legacy IE cache database' },
  // ── Email ────────────────────────────────────────────────────────────────────
  { key: 'email_outlook',     label: 'Outlook Email',                   desc: '.pst / .ost mailbox databases from Documents/Outlook Files and AppData', warn: true },
  { key: 'email_thunderbird', label: 'Thunderbird Email',               desc: 'Thunderbird profile SQLite databases and .msf index files' },
  // ── Messaging ────────────────────────────────────────────────────────────────
  { key: 'teams',             label: 'Microsoft Teams',                 desc: 'Teams logs.txt, IndexedDB, Local Storage — chat history traces' },
  { key: 'slack',             label: 'Slack',                           desc: 'Slack AppData/Roaming/Slack/logs — workspace activity logs' },
  { key: 'discord',           label: 'Discord',                         desc: 'Discord Local Storage — message and user data artifacts' },
  { key: 'signal',            label: 'Signal Desktop',                  desc: 'Signal databases/db.sqlite — encrypted message store' },
  { key: 'whatsapp',          label: 'WhatsApp Desktop',                desc: 'WhatsApp Desktop UWP package databases' },
  { key: 'telegram',          label: 'Telegram Desktop',                desc: 'Telegram tdata folder — session and message cache' },
  // ── Cloud ─────────────────────────────────────────────────────────────────────
  { key: 'cloud_onedrive',    label: 'OneDrive',                        desc: 'OneDrive sync databases and activity logs' },
  { key: 'cloud_google_drive',label: 'Google Drive',                    desc: 'Google DriveFS sync databases' },
  { key: 'cloud_dropbox',     label: 'Dropbox',                         desc: 'Dropbox sync metadata and activity JSON' },
  // ── Remote access ────────────────────────────────────────────────────────────
  { key: 'remote_access',     label: 'Remote Access Tools',             desc: 'AnyDesk traces/config, TeamViewer logs — lateral movement indicators' },
  { key: 'rdp',               label: 'RDP / Terminal Services',         desc: 'Terminal Server Client cache — bitmap tiles from past RDP sessions' },
  { key: 'ssh_ftp',           label: 'SSH / FTP Clients',               desc: 'known_hosts, PuTTY sessions, WinSCP.ini — remote connection history' },
  // ── Applications & user data ─────────────────────────────────────────────────
  { key: 'lnk',               label: 'LNK / Recent Items',              desc: 'Shell link files from all user Recent folders' },
  { key: 'tasks',             label: 'Scheduled Tasks (legacy key)',     desc: 'Alias for persistence — kept for backwards compatibility' },
  { key: 'office',            label: 'Office MRU',                      desc: 'Office Recent Documents list and trusted document registry' },
  { key: 'dev_tools',         label: 'Dev Tools',                       desc: '.gitconfig, .git-credentials, PowerShell history, .aws/credentials, .azure tokens' },
  { key: 'password_managers', label: 'Password Managers',               desc: 'KeePass .kdbx databases found in user directories' },
  { key: 'database_clients',  label: 'Database Clients',                desc: 'SSMS connection configs, DBeaver workspace files' },
  { key: 'gaming',            label: 'Gaming Platforms',                desc: 'Steam .vdf files, Epic Games Launcher logs' },
  { key: 'windows_apps',      label: 'Windows Apps (UWP)',              desc: 'Sticky Notes, Cortana — UWP package SQLite stores' },
  { key: 'wsl',               label: 'WSL',                             desc: 'Ubuntu/Debian WSL rootfs /etc — passwd, shadow, bashrc' },
  // ── Infrastructure ───────────────────────────────────────────────────────────
  { key: 'vpn',               label: 'VPN Config',                      desc: 'OpenVPN .ovpn profiles, WireGuard .conf files from ProgramData' },
  { key: 'iis_web',           label: 'IIS Web Server',                  desc: 'inetpub/logs .log files, applicationHost.config — web server forensics' },
  { key: 'active_directory',  label: 'Active Directory',                desc: 'Windows/NTDS/ntds.dit + edb.log — full AD database', warn: true },
  { key: 'virtualization',    label: 'Virtualization',                  desc: 'Hyper-V .vhd / .vhdx inventory from ProgramData' },
  { key: 'recovery',          label: 'Recovery / VSS',                  desc: 'System Volume Information — VSS snapshot metadata' },
  { key: 'printing',          label: 'Print Spool',                     desc: 'Windows/System32/spool/PRINTERS — spooled print jobs' },
  // ── Live-only ────────────────────────────────────────────────────────────────
  { key: 'triage',            label: 'Live System Triage',              desc: 'systeminfo, netstat, tasklist, services, installed software — live OS only' },
  // ── Heavy / opt-in ───────────────────────────────────────────────────────────
  { key: 'pe',                label: 'PE / Executable Binaries',        desc: 'EXE/DLL/PS1 from Temp, Downloads, AppData — feeds PE Analysis, YARA, strings', warn: true },
  { key: 'documents',         label: 'Office Documents & PDFs',         desc: 'DOCX, XLSX, PPTX, PDF from Documents/Downloads/Desktop — feeds OLE analysis', warn: true },
  { key: 'memory',            label: 'Live Memory Dump',                desc: 'Physical memory via WinPmem — 4–64 GB, requires winpmem_mini_x64_rc2.exe beside the script', warn: true },
  { key: 'memory_artifacts',  label: 'Memory Artifacts (dead-box)',     desc: 'pagefile.sys, hiberfil.sys, swapfile.sys — from mounted/external volume', warn: true },
  // ── On-demand file fetch ──────────────────────────────────────────────────────
  { key: 'file_search',       label: 'File Search (regex / name)',      desc: 'Fetch arbitrary files by filename, glob, or re: regex — set patterns below', warn: true },
]

const LINUX_ARTIFACTS = [
  { key: 'logs',      label: 'System Logs',          desc: '/var/log — auth.log, syslog, kern.log, audit, journalctl export' },
  { key: 'history',   label: 'Shell Histories',      desc: '.bash_history, .zsh_history for root and all users' },
  { key: 'config',    label: 'System Configuration', desc: '/etc/passwd, shadow, sudoers, hosts, ssh/sshd_config' },
  { key: 'cron',      label: 'Cron Jobs',            desc: 'cron.d, cron.daily, crontabs, systemd timers' },
  { key: 'ssh',       label: 'SSH Artifacts',        desc: 'known_hosts, authorized_keys, config (no private keys)' },
  { key: 'services',  label: 'System Services',      desc: 'Systemd units (/lib/systemd/system/, /etc/systemd/system/) and init.d scripts' },
  { key: 'network',   label: 'Network Captures',     desc: 'PCAP/PCAPNG from /var/log, /tmp — live tcpdump if none found' },
  { key: 'suricata',  label: 'Suricata IDS Logs',    desc: 'EVE JSON alerts from /var/log/suricata' },
  { key: 'edr',       label: 'EDR / AV Logs',        desc: 'auditd, Falco, osquery, CrowdStrike Falcon, SentinelOne, Wazuh alerts' },
  { key: 'antivirus', label: 'Antivirus / EDR',      desc: 'ClamAV, Trend Micro ds_agent, Defender (mdatp), Falcon, SentinelOne, Sophos SPL, ESET, Kaspersky, rkhunter/chkrootkit logs' },
  { key: 'sysmon',    label: 'Sysmon For Linux',     desc: 'config.xml, /opt/sysmon state, sysmon-tagged journal events' },
  { key: 'triage',    label: 'Live System Triage',   desc: 'ps, ss, ip, last, lsmod, installed packages' },
  { key: 'pe',        label: 'ELF / Binaries',       desc: 'Suspicious binaries from /tmp, /var/tmp, ~/Downloads — feeds PE Analysis, YARA', warn: true },
  { key: 'documents', label: 'Office Documents & PDFs', desc: 'DOCX, XLSX, PPTX, PDF from home directories — feeds OLE analysis', warn: true },
  { key: 'memory',    label: 'Memory Dump',          desc: 'Physical memory via avml or /dev/fmem — 4–64 GB, requires root + avml in PATH', warn: true },
  { key: 'file_search', label: 'File Search (regex / name)', desc: 'Fetch arbitrary files by filename, glob, or re: regex — set patterns below', warn: true },
]

const MACOS_ARTIFACTS = [
  { key: 'logs',      label: 'System Logs',          desc: '/var/log, ASL, Unified Logging export, system.log' },
  { key: 'history',   label: 'Shell Histories',      desc: '.bash_history, .zsh_history, fish_history for root and all users' },
  { key: 'config',    label: 'System Configuration', desc: '/etc/hosts, sudoers, ssh/sshd_config, /etc/passwd' },
  { key: 'cron',      label: 'Cron / launchd',       desc: 'User crontabs, /etc/cron.d, launchd timer plists' },
  { key: 'ssh',       label: 'SSH Artifacts',        desc: 'known_hosts, authorized_keys, config (no private keys)' },
  { key: 'plist',     label: 'Preference Plists',    desc: '/Library/Preferences, ~/Library/Preferences — app prefs and hidden settings' },
  { key: 'services',  label: 'LaunchAgents/Daemons', desc: '/Library/LaunchAgents, /Library/LaunchDaemons, ~/Library/LaunchAgents — persistence' },
  { key: 'network',   label: 'Network Captures',     desc: 'PCAP/PCAPNG from /var/log, /tmp — live tcpdump if none found' },
  { key: 'browser',   label: 'Browsers',             desc: 'Safari History.db, Cookies, Bookmarks.plist; Chrome/Firefox if installed' },
  { key: 'edr',       label: 'EDR / AV Logs',        desc: 'CrowdStrike Falcon for Mac, Carbon Black, Jamf, Kandji, osquery' },
  { key: 'triage',    label: 'Live System Triage',   desc: 'ps, netstat, launchctl list, system_profiler, sw_vers' },
  { key: 'pe',        label: 'Mach-O Binaries',      desc: 'Suspicious binaries from /tmp, ~/Downloads — feeds YARA, strings', warn: true },
  { key: 'documents', label: 'Office Documents & PDFs', desc: 'DOCX, XLSX, PPTX, PDF from home directories', warn: true },
  { key: 'memory',    label: 'Memory Dump',          desc: 'Physical memory via osxpmem — requires root + osxpmem in PATH', warn: true },
  { key: 'file_search', label: 'File Search (regex / name)', desc: 'Fetch arbitrary files by filename, glob, or re: regex — set patterns below', warn: true },
]

const DC_EXTRA_ARTIFACTS = [
  { key: 'evtx',    label: 'Event Logs (EVTX)',             desc: 'Security, ADDS replication, Kerberos, NTDS audit events' },
  { key: 'registry',label: 'Registry Hives',               desc: 'SYSTEM, SOFTWARE, SAM, SECURITY, Group Policy state' },
  { key: 'triage',  label: 'Live AD Triage',               desc: 'nltest, netdom, Get-ADUser/Group/GPO snapshots, trust enumeration' },
]

const PROXY_ARTIFACTS = [
  { key: 'logs',    label: 'Proxy / Access Logs',           desc: '/var/log/squid, /var/log/nginx, /var/log/haproxy, /var/log/apache2' },
  { key: 'config',  label: 'Proxy / Firewall Config',      desc: '/etc/squid, /etc/nginx, /etc/haproxy, /etc/iptables, nftables rules' },
  { key: 'triage',  label: 'Live Network Triage',          desc: 'Active connections, routing table, ARP cache, loaded kernel modules' },
  { key: 'network', label: 'Live PCAP Snapshot',           desc: 'Short tcpdump capture on primary interfaces (5 min, 500 MB cap)' },
  { key: 'ssh',     label: 'SSH Artifacts',                desc: 'known_hosts, authorized_keys, sshd_config' },
]

const NS_ARTIFACTS = [
  { key: 'logs',    label: 'DNS Query Logs',               desc: '/var/log/named, /var/log/bind, /var/log/unbound, journalctl' },
  { key: 'config',  label: 'DNS Configuration',            desc: '/etc/named.conf, /etc/bind, zone files, resolv.conf' },
  { key: 'triage',  label: 'Live System Triage',           desc: 'Running processes, open ports, installed packages' },
  { key: 'ssh',     label: 'SSH Artifacts',                desc: 'known_hosts, authorized_keys, sshd_config' },
]

// ── Platform definitions ──────────────────────────────────────────────────────

const PLATFORMS = [
  {
    id: 'win',
    label: 'Windows',
    group: 'Endpoint',
    Icon: Monitor,
    color: 'text-blue-600',
    bg: 'bg-blue-50',
    border: 'border-blue-200',
    selectedBorder: 'border-blue-500',
    selectedBg: 'bg-blue-50',
    desc: 'Live system, mounted directory (--path), or external disk (--disk)',
    tip: 'No Python needed — run.bat auto-downloads a portable Python if the target has none (pass -Offline to require a bundled/system one).',
    artifacts: WINDOWS_ARTIFACTS,
  },
  {
    id: 'linux',
    label: 'Linux',
    group: 'Endpoint',
    Icon: Terminal,
    color: 'text-emerald-600',
    bg: 'bg-emerald-50',
    border: 'border-emerald-200',
    selectedBorder: 'border-emerald-500',
    selectedBg: 'bg-emerald-50',
    desc: 'Workstation or server — run as root',
    tip: 'No Python needed — run.sh auto-downloads a portable Python if the target has none (pass --offline to require a bundled/system one).',
    artifacts: LINUX_ARTIFACTS,
  },
  {
    id: 'macos',
    label: 'macOS',
    group: 'Endpoint',
    Icon: Terminal,
    color: 'text-sky-600',
    bg: 'bg-sky-50',
    border: 'border-sky-200',
    selectedBorder: 'border-sky-500',
    selectedBg: 'bg-sky-50',
    desc: 'Workstation or laptop — run as root or with sudo',
    tip: 'No Python needed — run.sh auto-downloads a portable Python if absent. SIP must allow /var/log access for full coverage.',
    artifacts: MACOS_ARTIFACTS,
  },
  {
    id: 'win',
    label: 'Domain Controller',
    group: 'Endpoint',
    Icon: Monitor,
    color: 'text-indigo-600',
    bg: 'bg-indigo-50',
    border: 'border-indigo-200',
    selectedBorder: 'border-indigo-500',
    selectedBg: 'bg-indigo-50',
    desc: 'Windows — AD events, NTDS, GPO, trust info',
    tip: 'Run as Domain Admin. Collects AD-specific event channels and Group Policy state.',
    defaultCollect: ['evtx','registry','triage'],
    artifacts: DC_EXTRA_ARTIFACTS,
  },
  {
    id: 'linux',
    label: 'Proxy / Firewall',
    group: 'Network',
    Icon: Terminal,
    color: 'text-orange-600',
    bg: 'bg-orange-50',
    border: 'border-orange-200',
    selectedBorder: 'border-orange-500',
    selectedBg: 'bg-orange-50',
    desc: 'Linux-based — Squid, Nginx, HAProxy, iptables',
    tip: 'Run as root on the proxy or firewall host. Collects access logs, config and a PCAP snapshot.',
    defaultCollect: ['logs','config','triage','network'],
    artifacts: PROXY_ARTIFACTS,
  },
  {
    id: 'linux',
    label: 'Nameserver',
    group: 'Network',
    Icon: Terminal,
    color: 'text-cyan-600',
    bg: 'bg-cyan-50',
    border: 'border-cyan-200',
    selectedBorder: 'border-cyan-500',
    selectedBg: 'bg-cyan-50',
    desc: 'Linux-based — BIND, Unbound, PowerDNS',
    tip: 'Run as root on the DNS server. Captures query logs, zone files, and config.',
    defaultCollect: ['logs','config','triage'],
    artifacts: NS_ARTIFACTS,
  },
  {
    id: 'py',
    label: 'Generic (Python)',
    group: 'Other',
    Icon: FileCode,
    color: 'text-violet-600',
    bg: 'bg-violet-50',
    border: 'border-violet-200',
    selectedBorder: 'border-violet-500',
    selectedBg: 'bg-violet-50',
    desc: 'Auto-detects OS at runtime — Windows + Linux + macOS',
    tip: 'Best when the target already has Python 3.8+. Manually select artifacts below.',
    artifacts: [...WINDOWS_ARTIFACTS, ...LINUX_ARTIFACTS, ...MACOS_ARTIFACTS].filter(
      (a, i, arr) => arr.findIndex(b => b.key === a.key) === i
    ),
  },
]

const PLATFORM_GROUPS = ['Endpoint', 'Network', 'Other']

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Collector() {
  const [step, setStep]           = useState(1)
  const [platIdx, setPlatIdx]     = useState(null)
  const [selected, setSelected]   = useState(new Set())
  const [caseName, setCaseName]   = useState('')
  const [downloading, setDownloading]   = useState(false)
  const [downloaded, setDownloaded]     = useState(false)
  const [fetchPatterns, setFetchPatterns]   = useState('')   // file_search: one pattern per line
  const [collectionMode, setCollectionMode] = useState('live')   // 'live' | 'path' | 'disk'
  const [collectionPath, setCollectionPath] = useState('')
  const [collectionDisk, setCollectionDisk] = useState('')
  const [bitlockerKey,   setBitlockerKey]   = useState('')
  const [skipProblematic, setSkipProblematic] = useState(false)
  const [uploadMode, setUploadMode]         = useState('none')  // 'none' | 'citadel'
  // Optional: embed a portable Python interpreter in the bundle so the target
  // needs no Python install. '' = none. See API /collector/python-embeds.
  const [includePython, setIncludePython]   = useState('')
  const [pythonEmbeds,  setPythonEmbeds]    = useState([])
  useEffect(() => {
    api.collector.pythonEmbeds()
      .then(r => setPythonEmbeds(r.targets || []))
      .catch(() => {})
  }, [])
  const [uploadApiUrl, setUploadApiUrl]     = useState(() => window.location.origin)
  const [uploadApiToken, setUploadApiToken] = useState(() => localStorage.getItem('fo_token') || '')

  // Case selector (unified — drives both ZIP filename and upload target)
  const [cases, setCases]       = useState([])
  const [selectedCase, setSelectedCase] = useState(null)  // { case_id, name }
  const [caseSearch, setCaseSearch]     = useState('')
  const [caseDropOpen, setCaseDropOpen] = useState(false)
  const caseDropRef = useRef(null)

  // S3 uploader — shown in quick-tools bar when S3 triage is configured AND user is admin
  const [s3TriageConfigured,      setS3TriageConfigured]      = useState(false)
  const [downloadingUploader,     setDownloadingUploader]     = useState(false)
  const [downloadedUploader,      setDownloadedUploader]      = useState(false)
  // S3 bootstrap
  const [bootstrapPlatform,       setBootstrapPlatform]       = useState('ps1')  // 'ps1' | 'sh'
  const [bootstrapExpiry,         setBootstrapExpiry]         = useState(24)
  const [downloadingBootstrap,    setDownloadingBootstrap]    = useState(false)
  const [downloadedBootstrap,     setDownloadedBootstrap]     = useState(false)
  const [bootstrapScriptText,     setBootstrapScriptText]     = useState('')
  const [bootstrapCopied,         setBootstrapCopied]         = useState(false)
  const [bootstrapB64Copied,      setBootstrapB64Copied]      = useState(false)
  const [bootstrapError,          setBootstrapError]          = useState('')
  const isAdmin = _currentUser()?.role === 'admin'
  // Authoritative catalog from the backend ({ win, linux, macos }); null until
  // loaded or on failure, in which case the bundled arrays below are the fallback.
  const [catalog, setCatalog] = useState(null)
  // Section render order per platform, e.g. { win: ['Core System', ...] }
  const [groupOrder, setGroupOrder] = useState(null)

  useEffect(() => {
    api.cases.list()
      .then(r => setCases(r.cases || []))
      .catch(() => {})
  }, [])

  useEffect(() => {
    let live = true
    api.collector.categories()
      .then(r => {
        if (!live || !r?.platforms) return
        setCatalog(r.platforms)
        if (r.group_order) setGroupOrder(r.group_order)
      })
      .catch(() => {})   // silent — keep bundled fallback
    return () => { live = false }
  }, [])

  useEffect(() => {
    // Probe configured status — admin gets the full config object, analysts get
    // a presence-only flag from /s3-triage/status. Either way the UI can offer
    // the presigned-URL bundle to anyone authenticated.
    if (isAdmin) {
      api.s3Triage.getConfig()
        .then(cfg => setS3TriageConfigured(!!(cfg?.endpoint)))
        .catch(() => {})
    } else {
      api.s3Triage.status()
        .then(s => setS3TriageConfigured(!!s?.configured))
        .catch(() => {})
    }
  }, [isAdmin])

  useEffect(() => {
    function handleClickOutside(e) {
      if (caseDropRef.current && !caseDropRef.current.contains(e.target)) setCaseDropOpen(false)
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const filteredCases = useMemo(() =>
    caseSearch.trim() ? cases.filter(c => (c.name || '').toLowerCase().includes(caseSearch.toLowerCase())) : cases,
    [cases, caseSearch]
  )

  // Defensively coerce a fetched catalog list into the {key,label,desc,warn}
  // shape the UI expects. Unknown/garbage entries are dropped, fields stringified.
  const sanitizeArtifacts = (list) => {
    if (!Array.isArray(list)) return null
    const clean = list
      .filter(a => a && typeof a.key === 'string' && /^[a-z0-9_]+$/.test(a.key))
      .map(a => ({
        key:   a.key,
        label: String(a.label ?? a.key),
        desc:  String(a.desc ?? ''),
        warn:  a.warn === true,
        group: typeof a.group === 'string' && a.group ? a.group : 'Artifacts',
      }))
    return clean.length ? clean : null
  }

  // PLATFORMS with base win/linux/macos artifact lists swapped for the backend
  // catalog when available. Curated presets (DC/Proxy/NS) are left untouched.
  const platforms = useMemo(() => {
    if (!catalog) return PLATFORMS
    const win   = sanitizeArtifacts(catalog.win)
    const linux = sanitizeArtifacts(catalog.linux)
    const macos = sanitizeArtifacts(catalog.macos)
    const dedupe = (arr) => arr.filter((a, i) => arr.findIndex(b => b.key === a.key) === i)
    const generic = dedupe([
      ...(win || WINDOWS_ARTIFACTS), ...(linux || LINUX_ARTIFACTS), ...(macos || MACOS_ARTIFACTS),
    ])
    return PLATFORMS.map(p => {
      if (p.artifacts === WINDOWS_ARTIFACTS && win)   return { ...p, artifacts: win }
      if (p.artifacts === LINUX_ARTIFACTS   && linux) return { ...p, artifacts: linux }
      if (p.artifacts === MACOS_ARTIFACTS   && macos) return { ...p, artifacts: macos }
      if (p.id === 'py')                              return { ...p, artifacts: generic }
      return p
    })
  }, [catalog])

  const platformDef = platIdx !== null ? platforms[platIdx] : null
  const artifacts   = platformDef?.artifacts || []

  // Pre-select artifacts when platform chosen; warn=true items default OFF
  useEffect(() => {
    if (!platformDef) return
    const defaults = platformDef.defaultCollect
      ? new Set(platformDef.defaultCollect)
      : new Set(platformDef.artifacts.filter(a => !a.warn).map(a => a.key))
    setSelected(defaults)
    setStep(1)
  }, [platIdx])

  function toggleArtifact(key) {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  function toggleAll() {
    setSelected(
      selected.size === artifacts.length
        ? new Set()
        : new Set(artifacts.map(a => a.key))
    )
  }

  // Bucket the flat artifact list into ordered sections for the wizard grid.
  // Order: the platform's group_order from the API, then any leftover groups in
  // first-seen order. Falls back to a single section when nothing is grouped.
  const groupedArtifacts = useMemo(() => {
    const buckets = new Map()
    for (const a of artifacts) {
      const g = a.group || 'Artifacts'
      if (!buckets.has(g)) buckets.set(g, [])
      buckets.get(g).push(a)
    }
    const preferred = (platformDef && groupOrder?.[platformDef.id]) || []
    const ordered = [
      ...preferred.filter(g => buckets.has(g)),
      ...[...buckets.keys()].filter(g => !preferred.includes(g)),
    ]
    return ordered.map(g => ({ group: g, items: buckets.get(g) }))
  }, [artifacts, platformDef, groupOrder])

  // file_search patterns — split on newlines/commas, only relevant when selected
  const fetchPatternList = useMemo(
    () => (selected.has('file_search')
      ? fetchPatterns.split(/[\n,]/).map(s => s.trim()).filter(Boolean)
      : []),
    [selected, fetchPatterns],
  )

  function handleDownload() {
    setDownloading(true)
    setDownloaded(false)
    const url = api.collector.packageUrl({
      categories:      [...selected],
      caseName:        caseName.trim() || undefined,
      platform:        platformDef?.id || undefined,
      path:            collectionMode === 'path' ? collectionPath.trim() || undefined : undefined,
      disk:            collectionMode === 'disk' ? collectionDisk.trim() || undefined : undefined,
      skipProblematic: skipProblematic || undefined,
      fetchPatterns:   fetchPatternList.length ? fetchPatternList : undefined,
      apiUrl:          uploadMode === 'citadel' ? uploadApiUrl.trim() || undefined : undefined,
      caseId:          uploadMode === 'citadel' ? selectedCase?.case_id || undefined : undefined,
      apiToken:        uploadMode === 'citadel' ? uploadApiToken.trim() || undefined : undefined,
      uploadMode:      uploadMode === 's3-presigned' ? 's3_presigned' : undefined,
      includePython:   includePython || undefined,
    })
    const a = document.createElement('a')
    a.href = url
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    setTimeout(() => { setDownloading(false); setDownloaded(true) }, 1200)
  }

  async function handleGenerateBootstrap() {
    setDownloadingBootstrap(true)
    setDownloadedBootstrap(false)
    setBootstrapScriptText('')
    setBootstrapCopied(false)
    setBootstrapError('')
    try {
      const blob = await api.collector.s3Bootstrap({
        categories:   [...selected],
        caseName:     caseName.trim() || undefined,
        caseId:       selectedCase?.case_id || undefined,
        fetchPatterns: fetchPatternList.length ? fetchPatternList : undefined,
        apiUrl:       uploadMode === 'citadel' ? uploadApiUrl.trim() || undefined : undefined,
        apiToken:     uploadMode === 'citadel' ? uploadApiToken.trim() || undefined : undefined,
        expiresHours: bootstrapExpiry,
        platform:     bootstrapPlatform,
        pathArg:      bootstrapPlatform === 'sh' && collectionMode === 'path' ? collectionPath.trim() || undefined : undefined,
        diskArg:      bootstrapPlatform === 'sh' && collectionMode === 'disk' ? collectionDisk.trim() || undefined : undefined,
        bitlockerKey: bootstrapPlatform === 'sh' && collectionMode === 'disk' && bitlockerKey.trim() ? bitlockerKey.trim() : undefined,
      })
      const text = await blob.text()
      setBootstrapScriptText(text)
    } catch (err) {
      setBootstrapError(err.message)
    } finally {
      setDownloadingBootstrap(false)
    }
  }

  async function handleDownloadBootstrap() {
    if (!bootstrapScriptText) return
    const ext      = bootstrapPlatform === 'ps1' ? '.ps1' : '.sh'
    const safeName = (caseName.trim() || 'bootstrap').replace(/[^\w-]/g, '_').slice(0, 40)
    const filename = `fo-bootstrap-${safeName}${ext}`
    const blob = new Blob([bootstrapScriptText], { type: 'text/plain' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    setDownloadedBootstrap(true)
  }

  async function handleCopyBootstrap() {
    if (!bootstrapScriptText) return
    await navigator.clipboard.writeText(bootstrapScriptText)
    setBootstrapCopied(true)
    setTimeout(() => setBootstrapCopied(false), 2000)
  }

  async function handleCopyBootstrapB64() {
    if (!bootstrapScriptText) return
    const b64 = btoa(unescape(encodeURIComponent(bootstrapScriptText)))
    const oneliner = `echo "${b64}" | base64 -d | bash`
    await navigator.clipboard.writeText(oneliner)
    setBootstrapB64Copied(true)
    setTimeout(() => setBootstrapB64Copied(false), 2000)
  }

  async function handleDownloadUploader() {
    setDownloadingUploader(true)
    setDownloadedUploader(false)
    try {
      const blob = await api.collector.uploaderPresigned()
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = 'fo-uploader-presigned.zip'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      setDownloadedUploader(true)
    } catch (err) {
      alert('Failed to generate presigned uploader: ' + err.message)
    } finally {
      setDownloadingUploader(false)
    }
  }

  const stepLabels = ['Platform', 'Artifacts', 'Download']

  // ── render ────────────────────────────────────────────────────────────────
  return (
    <div className="h-full overflow-y-auto bg-gray-50">
      <div className="px-6 py-6">

        {/* Page header */}
        <div className="mb-4">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-lg font-bold text-brand-text">Artifact Collector</h1>
            <span className="badge text-[10px] bg-brand-accentlight text-brand-accent border border-brand-accent/30">
              Powered by Talon
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-0.5">
            Generate a pre-configured Talon collection script for live systems, mounted directories, or external drives.
            For server-side collection from a disk image already in a case, use <strong>Ingest → Harvest</strong>.
          </p>
        </div>

        {/* ── How the Collector works ──────────────────────────────── */}
        <div className="mb-6 card overflow-hidden">
          <div className="px-4 py-2.5 bg-gray-100 border-b border-gray-200">
            <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">How to use</span>
          </div>

          {/* 3 steps */}
          <div className="grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-gray-100 border-b border-gray-100">
            {[
              { n: '1', title: 'Generate script', body: 'Pick platform + artifacts, download fo-harvester.py + config.json.' },
              { n: '2', title: 'Run on target',   body: 'Python 3.8+, no extra packages on Windows. Run as Administrator/root.' },
              { n: '3', title: 'Upload to case',  body: 'ZIP lands in ./output/. Upload via Case → Add Evidence.' },
            ].map(({ n, title, body }) => (
              <div key={n} className="flex items-start gap-2.5 px-4 py-3">
                <span className="w-5 h-5 rounded-full bg-brand-accent text-white text-[10px] font-bold flex items-center justify-center flex-shrink-0 mt-0.5">{n}</span>
                <div>
                  <p className="text-xs font-semibold text-brand-text">{title}</p>
                  <p className="text-[11px] text-gray-500 mt-0.5 leading-relaxed">{body}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Run modes */}
          <div className="divide-y divide-gray-100">
            {[
              { mode: 'Live OS',               cmd: 'python fo-harvester.py',                         notes: 'Admin (Win) / root (Linux/macOS)' },
              { mode: 'Dead-box path (Win)',    cmd: 'python fo-harvester.py --path D:\\',             notes: 'Point at mounted drive letter' },
              { mode: 'Dead-box path (Linux)',  cmd: 'python fo-harvester.py --path /mnt/windows',    notes: 'Mount with ntfs-3g first' },
              { mode: 'Dead-box disk (Linux)',  cmd: 'python fo-harvester.py --disk /dev/sdb',        notes: 'ntfs-3g + dislocker required' },
              { mode: 'Dead-box disk (Win)',    cmd: 'python fo-harvester.py --disk E:\\',            notes: 'manage-bde -unlock E: … first' },
            ].map(({ mode, cmd, notes }) => (
              <div key={mode} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 hover:bg-gray-100/50">
                <span className="text-[11px] font-medium text-brand-text w-44 flex-shrink-0">{mode}</span>
                <code className="text-[11px] font-mono text-brand-accent bg-gray-100 px-2 py-0.5 rounded flex-1 min-w-0">{cmd}</code>
                <span className="text-[11px] text-gray-500 flex-shrink-0">{notes}</span>
              </div>
            ))}
          </div>

          <div className="px-4 py-2 bg-amber-50 border-t border-amber-100 text-[11px] text-amber-700">
            <strong>Server-side BitLocker:</strong> Set the recovery key in Case → Files so uploaded .dd/.img files are decrypted automatically.
          </div>
        </div>

        {/* Quick tools — S3 uploader (presigned URLs, no creds — open to analysts) */}
        {s3TriageConfigured && (
          <div className="mb-5 flex items-center gap-3 p-3 bg-white border border-gray-200 rounded-xl shadow-sm">
            <Upload size={15} className="text-brand-accent flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-brand-text leading-tight">fo-uploader.zip</p>
              <p className="text-xs text-gray-500 truncate">
                S3 evidence uploader — up to{' '}
                <span className="text-brand-accent font-medium">3 files</span>
                {' '}via presigned URLs (24h, no credentials embedded).
              </p>
            </div>
            <button
              onClick={handleDownloadUploader}
              disabled={downloadingUploader}
              className={`btn-outline flex-shrink-0 text-xs py-1.5 ${downloadedUploader ? '!border-green-500 !text-green-700' : ''}`}
            >
              {downloadingUploader
                ? 'Preparing…'
                : downloadedUploader
                ? <><Check size={12} /> Downloaded</>
                : <><Download size={12} /> Download</>
              }
            </button>
          </div>
        )}

        {/* Step indicator */}
        <div className="flex items-center gap-0 mb-6 bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
          {stepLabels.map((label, i) => {
            const num    = i + 1
            const active = step === num
            const done   = step > num
            return (
              <button
                key={label}
                disabled={!done && !active}
                onClick={() => done && setStep(num)}
                className={`flex-1 flex items-center justify-center gap-2 py-3.5 text-sm font-medium
                            transition-colors border-r border-gray-100 last:border-r-0 ${
                  active
                    ? 'bg-brand-accent/5 text-brand-accent'
                    : done
                    ? 'text-gray-500 hover:text-brand-accent hover:bg-gray-50 cursor-pointer'
                    : 'text-gray-500 cursor-default'
                }`}
              >
                <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
                  active ? 'bg-brand-accent text-white' :
                  done   ? 'bg-green-500 text-white' :
                           'bg-gray-200 text-gray-500'
                }`}>
                  {done ? <Check size={10} /> : num}
                </span>
                {label}
              </button>
            )
          })}
        </div>

        {/* ── Step 1: Platform ─────────────────────────────────────────── */}
        {step === 1 && (
          <div className="space-y-5">
            {PLATFORM_GROUPS.map(group => {
              const groupPlatforms = platforms.map((p, i) => ({ ...p, _idx: i })).filter(p => p.group === group)
              if (groupPlatforms.length === 0) return null
              return (
                <div key={group}>
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-2">{group}</p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {groupPlatforms.map(({ _idx, label, Icon, desc, tip, selectedBorder, selectedBg, bg, color, border }) => {
                      const active = platIdx === _idx
                      return (
                        <button
                          key={_idx}
                          onClick={() => { setPlatIdx(_idx); setStep(1) }}
                          className={`card flex flex-col items-start gap-2.5 p-4 text-left cursor-pointer
                                      border-2 transition-all hover:shadow-md ${
                            active ? `${selectedBorder} ${selectedBg}` : `border-transparent`
                          }`}
                        >
                          <div className="flex items-center gap-2.5 w-full">
                            <div className={`w-9 h-9 rounded-lg ${bg} border ${border} flex items-center justify-center flex-shrink-0`}>
                              <Icon size={18} className={color} />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-semibold text-brand-text">{label}</div>
                              <div className="text-xs text-gray-500 truncate">{desc}</div>
                            </div>
                            {active && <Check size={14} className="text-brand-accent flex-shrink-0" />}
                          </div>
                          <div className="text-[11px] text-gray-500 leading-relaxed">{tip}</div>
                        </button>
                      )
                    })}
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {/* ── Step 2: Artifacts ─────────────────────────────────────── */}
        {step === 2 && platformDef && (
          <div className="card p-5">
            <div className="mb-4">
              <h3 className="text-sm font-semibold text-brand-text">
                {platformDef.label} artifact selection
              </h3>
              <p className="text-xs text-gray-500 mt-0.5">
                {selected.size} of {artifacts.length} artifact types selected
              </p>
            </div>

            {/* Shared picker — same component the Harvest tab uses */}
            <ArtifactSelector
              groups={groupedArtifacts}
              selected={selected}
              onToggle={toggleArtifact}
              onToggleGroup={(keys) => setSelected(prev => {
                const next = new Set(prev)
                const allOn = keys.every(k => next.has(k))
                keys.forEach(k => allOn ? next.delete(k) : next.add(k))
                return next
              })}
              onSelectAll={toggleAll}
              onScenario={(keys) => setSelected(new Set(keys))}
            />
            {selected.has('memory') && (
              <div className="mt-3 flex items-start gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800">
                <AlertTriangle size={13} className="flex-shrink-0 mt-0.5 text-amber-500" />
                <div>
                  <strong>Memory dumps are 4–64 GB and take 15–60 minutes.</strong>{' '}
                  Ensure storage is sufficient and upload timeouts are generous.
                </div>
              </div>
            )}
            {selected.has('file_search') && (
              <div className="mt-3 p-3 bg-amber-50 border border-amber-200 rounded-lg">
                <label className="flex items-center gap-1.5 text-xs font-semibold text-amber-800 mb-1.5">
                  <AlertTriangle size={13} className="text-amber-500" />
                  File Search patterns
                  <span className="font-normal text-amber-700">— one per line (or comma-separated)</span>
                </label>
                <textarea
                  value={fetchPatterns}
                  onChange={e => setFetchPatterns(e.target.value)}
                  rows={4}
                  spellCheck={false}
                  placeholder={'mimikatz*\nre:\\.(ps1|hta|vbs)$\nre:/temp/.*\\.exe$\nsuspicious.dll'}
                  className="w-full text-xs font-mono px-2.5 py-2 rounded-md border border-amber-300 bg-white focus:outline-none focus:ring-1 focus:ring-amber-400"
                />
                <p className="text-[11px] text-amber-700 mt-1.5 leading-relaxed">
                  <code>mimikatz*</code> = glob on filename · <code>re:PATTERN</code> = regex
                  (matched against full path when it contains <code>/</code>, else filename) ·
                  plain text = exact filename. Caps: 200 files, 100 MB each, 10-min sweep.
                </p>
                {fetchPatternList.length === 0 && (
                  <p className="text-[11px] text-red-600 mt-1">
                    No patterns set — File Search will collect nothing.
                  </p>
                )}
              </div>
            )}
          </div>
        )}

        {/* ── Step 3: Configure & Download ─────────────────────────── */}
        {step === 3 && (
          <div className="space-y-4">

            {/* Summary */}
            <div className="card p-4">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
                Configuration summary
              </h3>
              <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm mb-4">
                <SummaryRow label="Platform"  value={platformDef?.label} />
                <SummaryRow label="Artifacts" value={`${selected.size} types`} />
                {caseName.trim() && <SummaryRow label="Case name" value={caseName.trim()} mono />}
              </div>
              {/* Searchable case picker */}
              <div className="relative" ref={caseDropRef}>
                <label className="block text-xs font-medium text-gray-500 mb-1">
                  Link to case <span className="text-gray-500 font-normal">(optional)</span>
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={selectedCase ? selectedCase.name : caseSearch}
                    onChange={e => {
                      if (selectedCase) { setSelectedCase(null); setCaseName('') }
                      setCaseSearch(e.target.value)
                      setCaseDropOpen(true)
                    }}
                    onFocus={() => setCaseDropOpen(true)}
                    placeholder="Search cases…"
                    className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 pr-8
                               focus:outline-none focus:ring-2 focus:ring-brand-accent/30 focus:border-brand-accent"
                  />
                  {selectedCase && (
                    <button
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-600"
                      onClick={() => { setSelectedCase(null); setCaseName(''); setCaseSearch('') }}
                    >
                      <X size={13} />
                    </button>
                  )}
                </div>
                {caseDropOpen && !selectedCase && (
                  <div className="absolute z-10 w-full mt-1 bg-white border border-gray-200 rounded-lg shadow-lg max-h-44 overflow-y-auto">
                    {filteredCases.length === 0 ? (
                      <p className="px-3 py-2 text-xs text-gray-500">No matching cases</p>
                    ) : filteredCases.map(c => (
                      <button
                        key={c.case_id}
                        onMouseDown={() => {
                          setSelectedCase(c)
                          setCaseName(c.name)
                          setCaseSearch('')
                          setCaseDropOpen(false)
                        }}
                        className="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 flex items-center justify-between"
                      >
                        <span className="text-brand-text truncate">{c.name}</span>
                        <span className="text-xs text-gray-500 flex-shrink-0 ml-2">{c.case_id}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-500 mb-1">
                  Case name <span className="text-gray-500 font-normal">(optional — used in output ZIP filename)</span>
                </label>
                <input
                  type="text"
                  value={caseName}
                  onChange={e => setCaseName(e.target.value)}
                  placeholder="e.g. ACME-2024-IR01"
                  className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2
                             focus:outline-none focus:ring-2 focus:ring-brand-accent/30 focus:border-brand-accent
                             placeholder:text-gray-400"
                />
              </div>
            </div>

            {/* Collection mode */}
            <div className="card p-4">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
                Collection mode
              </h3>
              <div className="flex gap-2 mb-3">
                {[
                  { id: 'live', label: 'Live system',         hint: 'Run directly on target' },
                  { id: 'path', label: 'Dead-box — path',     hint: 'Mounted filesystem' },
                  { id: 'disk', label: 'Dead-box — raw disk', hint: 'Block device / image' },
                ].map(m => (
                  <button
                    key={m.id}
                    onClick={() => { setCollectionMode(m.id); if (m.id !== 'disk') setBitlockerKey('') }}
                    className={`flex-1 flex flex-col items-center gap-0.5 py-2.5 px-2 rounded-lg border text-xs font-medium transition-colors ${
                      collectionMode === m.id
                        ? 'border-brand-accent bg-brand-accent/5 text-brand-accent'
                        : 'border-gray-200 text-gray-500 hover:border-gray-300 hover:text-gray-700'
                    }`}
                  >
                    <span>{m.label}</span>
                    <span className={`text-[10px] font-normal ${collectionMode === m.id ? 'text-brand-accent/70' : 'text-gray-500'}`}>{m.hint}</span>
                  </button>
                ))}
              </div>
              {collectionMode === 'path' && (
                <div className="mb-3">
                  <label className="block text-xs font-medium text-gray-500 mb-1">
                    Mounted path <span className="text-gray-500 font-normal">(baked into config — run with zero args)</span>
                  </label>
                  <input
                    type="text"
                    value={collectionPath}
                    onChange={e => setCollectionPath(e.target.value)}
                    placeholder="e.g. /mnt/evidence  or  E:\\"
                    className="w-full text-sm font-mono border border-gray-200 rounded-lg px-3 py-2
                               focus:outline-none focus:ring-2 focus:ring-brand-accent/30 focus:border-brand-accent
                               placeholder:text-gray-400"
                  />
                </div>
              )}
              {collectionMode === 'disk' && (
                <div className="mb-3">
                  <label className="block text-xs font-medium text-gray-500 mb-1">
                    Block device / image <span className="text-gray-500 font-normal">(Linux only — ntfs-3g + dislocker required)</span>
                  </label>
                  <input
                    type="text"
                    value={collectionDisk}
                    onChange={e => setCollectionDisk(e.target.value)}
                    placeholder="e.g. /dev/sdb1  or  /images/disk.img"
                    className="w-full text-sm font-mono border border-gray-200 rounded-lg px-3 py-2
                               focus:outline-none focus:ring-2 focus:ring-brand-accent/30 focus:border-brand-accent
                               placeholder:text-gray-400"
                  />
                </div>
              )}
              {collectionMode === 'disk' && (
                <div className="mb-3">
                  <label className="block text-xs font-medium text-gray-500 mb-1">
                    BitLocker recovery key{' '}
                    <span className="text-gray-500 font-normal">(optional)</span>
                  </label>
                  <input
                    type="text"
                    value={bitlockerKey}
                    onChange={e => setBitlockerKey(e.target.value)}
                    placeholder="123456-123456-123456-123456-123456-123456-123456-123456"
                    className="w-full text-sm font-mono border border-gray-200 rounded-lg px-3 py-2
                               focus:outline-none focus:ring-2 focus:ring-brand-accent/30 focus:border-brand-accent
                               placeholder:text-gray-400"
                  />
                </div>
              )}
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={skipProblematic}
                  onChange={e => setSkipProblematic(e.target.checked)}
                  className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent/30"
                />
                <span className="text-xs text-gray-600">
                  Skip categories that fail in dead-box mode{' '}
                  <span className="text-gray-500">(triage, live network, memory)</span>
                </span>
              </label>
            </div>

            {/* Auto-upload config */}
            <div className="card p-4">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
                Auto-upload after collection
              </h3>
              <div className="flex gap-2 mb-3">
                {[
                  { id: 'none',          label: 'None',              hint: 'Save ZIP locally' },
                  { id: 'citadel',        label: 'Upload to Citadel',  hint: 'Direct API upload' },
                  ...(s3TriageConfigured ? [{ id: 's3-presigned', label: 'Upload to S3', hint: 'Presigned URL (no credentials stored)' }] : []),
                ].map(m => (
                  <button
                    key={m.id}
                    onClick={() => setUploadMode(m.id)}
                    className={`flex-1 flex flex-col items-center gap-0.5 py-2.5 px-2 rounded-lg border text-xs font-medium transition-colors ${
                      uploadMode === m.id
                        ? 'border-brand-accent bg-brand-accent/5 text-brand-accent'
                        : 'border-gray-200 text-gray-500 hover:border-gray-300 hover:text-gray-700'
                    }`}
                  >
                    <span>{m.label}</span>
                    <span className={`text-[10px] font-normal ${uploadMode === m.id ? 'text-brand-accent/70' : 'text-gray-500'}`}>{m.hint}</span>
                  </button>
                ))}
              </div>
              {uploadMode === 'citadel' && (
                <div className="space-y-2">
                  <div>
                    <label className="block text-xs font-medium text-gray-500 mb-1">Citadel API URL</label>
                    <input type="text" value={uploadApiUrl} onChange={e => setUploadApiUrl(e.target.value)}
                      placeholder="https://citadel.your.org"
                      className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-brand-accent/30 focus:border-brand-accent placeholder:text-gray-400" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-500 mb-1">
                      API token <span className="text-gray-500 font-normal">(pre-filled from session)</span>
                    </label>
                    <input type="password" value={uploadApiToken} onChange={e => setUploadApiToken(e.target.value)}
                      placeholder="eyJ…"
                      className="w-full text-sm font-mono border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-brand-accent/30 focus:border-brand-accent placeholder:text-gray-400" />
                    <p className="mt-1 text-[11px] text-gray-500">This token will be embedded in the package. For shared or field deployments, consider using a dedicated analyst account instead of your personal token.</p>
                  </div>
                </div>
              )}
            </div>

            {/* Download package */}
            <div className="card p-4">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                Download Package
              </h3>
              <p className="text-xs text-gray-500 mb-3 leading-relaxed">
                Downloads <code className="text-[10px] bg-gray-100 px-1 py-0.5 rounded">fo-harvester.zip</code> — everything baked into{' '}
                <code className="text-[10px] bg-gray-100 px-1 py-0.5 rounded">config.json</code>, runs with zero arguments.
                {!includePython && <> Requires <strong className="text-gray-500">Python 3.8+</strong> on the target.</>}
                {includePython && <> Self-contained — bundled interpreter, no install needed on target.</>}
              </p>

              {/* Bundle Python interpreter */}
              <div className="mb-3">
                <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">
                  Bundle Python interpreter (offline targets)
                </label>
                <select
                  value={includePython}
                  onChange={e => setIncludePython(e.target.value)}
                  className="input text-xs h-8 w-full"
                >
                  <option value="">No — target must have Python 3.8+ installed</option>
                  {pythonEmbeds.map(t => (
                    <option key={t.id} value={t.id}>
                      Include {t.label} (+{t.size_mb} MB){t.cached ? ' • cached' : ' • first download ~1 min'}
                    </option>
                  ))}
                </select>
                {includePython && (
                  <p className="text-[10px] text-gray-500 mt-1">
                    Bundle contains a portable interpreter under{' '}
                    <code className="bg-gray-100 px-1 rounded">
                      {includePython === 'win-x64' ? 'python-embed/' : 'python3/'}
                    </code>. run.bat / run.sh detect and use it automatically.
                  </p>
                )}
              </div>

              <button
                className={`btn-primary w-full justify-center h-10 gap-2 ${downloaded ? '!bg-green-600' : ''}`}
                onClick={handleDownload}
                disabled={selected.size === 0 || downloading}
              >
                {downloading
                  ? 'Preparing…'
                  : downloaded
                  ? <><Check size={14} /> fo-harvester.zip downloaded</>
                  : <><Download size={14} /> Download fo-harvester.zip</>
                }
              </button>

              {downloaded && (
                <div className="mt-4 bg-gray-950 rounded-lg p-4 text-[11px] font-mono leading-relaxed space-y-2">
                  <div className="text-gray-500"># Extract fo-harvester.zip then run on the target machine</div>
                  {platformDef?.id === 'win' ? <>
                    {collectionMode === 'live' && (
                      <div>
                        <span className="text-gray-500"># Live OS (run as Administrator):</span>{'\n'}
                        <span className="text-green-400">python fo-harvester.py</span>
                      </div>
                    )}
                    {collectionMode === 'path' && (
                      <div>
                        <span className="text-gray-500"># Dead-box — mounted directory:</span>{'\n'}
                        <span className="text-green-400">
                          python fo-harvester.py --path {collectionPath || 'D:\\'}
                        </span>
                      </div>
                    )}
                    {collectionMode === 'disk' && (
                      <div>
                        <span className="text-gray-500"># Dead-box — raw device{bitlockerKey ? ' + BitLocker' : ''}:</span>{'\n'}
                        <span className="text-green-400">
                          python fo-harvester.py --disk {collectionDisk || 'E:\\'}
                          {bitlockerKey ? ` ^\n  --bitlocker-key ${bitlockerKey}` : ''}
                        </span>
                      </div>
                    )}
                  </> : <>
                    {collectionMode === 'live' && (
                      <div>
                        <span className="text-gray-500"># Live OS (run as root):</span>{'\n'}
                        <span className="text-green-400">python3 fo-harvester.py</span>
                      </div>
                    )}
                    {collectionMode === 'path' && (
                      <div>
                        <span className="text-gray-500"># Dead-box — mounted directory:</span>{'\n'}
                        <span className="text-green-400">
                          python3 fo-harvester.py --path {collectionPath || '/mnt/windows'}
                        </span>
                      </div>
                    )}
                    {collectionMode === 'disk' && (
                      <div>
                        <span className="text-gray-500"># Dead-box — raw device{bitlockerKey ? ' + BitLocker' : ''}:</span>{'\n'}
                        <span className="text-green-400">
                          python3 fo-harvester.py --disk {collectionDisk || '/dev/sdb1'}
                          {bitlockerKey ? ` \\\n  --bitlocker-key ${bitlockerKey}` : ''}
                        </span>
                      </div>
                    )}
                  </>}
                  {bitlockerKey && (
                    <div className="text-amber-400 pt-1"># ⚠ Key shown above — do not share this terminal block</div>
                  )}
                  <div className="text-gray-500 pt-1"># Output ZIP is created in ./output/ — upload via Case → Ingest</div>
                </div>
              )}
            </div>
            {/* S3 Bootstrap — presigned URLs only, no creds in script — open to analysts */}
            {s3TriageConfigured && (
              <div className="card p-4 border-2 border-dashed border-brand-accent/30">
                <div className="flex items-center gap-2 mb-1">
                  <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    S3 Bootstrap Script
                  </h3>
                  <span className="text-[10px] bg-brand-accent/10 text-brand-accent px-1.5 py-0.5 rounded font-medium">Admin</span>
                </div>
                <p className="text-xs text-gray-500 mb-3 leading-relaxed">
                  Uploads the collector to S3, then returns a tiny script that{' '}
                  <strong className="text-gray-600">fetches the zip → runs collection → deletes local temp → deletes the zip from S3</strong>.
                  Share the script with the field operator — no credentials embedded.
                </p>

                {/* Platform + expiry */}
                <div className="flex gap-2 mb-3">
                  {[
                    { id: 'ps1', label: 'Windows', hint: 'PowerShell 5.1+' },
                    { id: 'sh',  label: 'Linux / macOS', hint: 'bash / curl' },
                  ].map(p => (
                    <button
                      key={p.id}
                      onClick={() => { setBootstrapPlatform(p.id); setDownloadedBootstrap(false) }}
                      className={`flex-1 flex flex-col items-center gap-0.5 py-2 px-2 rounded-lg border text-xs font-medium transition-colors ${
                        bootstrapPlatform === p.id
                          ? 'border-brand-accent bg-brand-accent/5 text-brand-accent'
                          : 'border-gray-200 text-gray-500 hover:border-gray-300'
                      }`}
                    >
                      <span>{p.label}</span>
                      <span className={`text-[10px] font-normal ${bootstrapPlatform === p.id ? 'text-brand-accent/70' : 'text-gray-500'}`}>{p.hint}</span>
                    </button>
                  ))}
                </div>

                <div className="flex items-center gap-2 mb-3 flex-wrap">
                  <label className="text-xs text-gray-500 flex-shrink-0">Expires in</label>
                  <select
                    value={bootstrapExpiry}
                    onChange={e => setBootstrapExpiry(Number(e.target.value))}
                    className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-brand-accent/30 focus:border-brand-accent"
                  >
                    {[
                      { v: 4,   l: '4 hours'  },
                      { v: 12,  l: '12 hours' },
                      { v: 24,  l: '24 hours' },
                      { v: 48,  l: '48 hours' },
                      { v: 168, l: '7 days'   },
                    ].map(({ v, l }) => <option key={v} value={v}>{l}</option>)}
                  </select>
                  <span className="text-[11px] text-gray-500">— URL and S3 object expire at the same time</span>
                </div>

                {collectionMode !== 'live' && (
                  <div className="mb-3 px-3 py-2 bg-brand-accent/5 border border-brand-accent/20 rounded-lg text-[11px] text-brand-accent/80 flex items-start gap-2">
                    <FolderOpen size={12} className="mt-0.5 flex-shrink-0" />
                    <span>
                      {collectionMode === 'path'
                        ? <><strong>path</strong>, <strong>case</strong>, <strong>categories</strong>{bitlockerKey ? ', and <strong>bitlocker_key</strong>' : ''} baked into config.json — script runs with no arguments</>
                        : <><strong>disk</strong>, <strong>case</strong>, <strong>categories</strong>{bitlockerKey ? ', and <strong>bitlocker_key</strong>' : ''} baked into config.json — script runs with no arguments</>
                      }
                    </span>
                  </div>
                )}

                {bootstrapError && (
                  <div className="mb-3 p-2.5 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">
                    {bootstrapError}
                  </div>
                )}

                <div className="flex gap-2">
                  <button
                    className="btn-outline flex-1 justify-center h-10 gap-2 text-sm !border-brand-accent !text-brand-accent hover:!bg-brand-accent/5"
                    onClick={handleGenerateBootstrap}
                    disabled={selected.size === 0 || downloadingBootstrap}
                  >
                    {downloadingBootstrap
                      ? 'Uploading to S3…'
                      : bootstrapScriptText
                      ? <><Check size={14} /> Generated — regenerate</>
                      : <>Generate ({bootstrapPlatform === 'ps1' ? '.ps1' : '.sh'})</>
                    }
                  </button>
                  {bootstrapScriptText && bootstrapPlatform === 'sh' && (
                    <button
                      className={`btn-outline h-10 px-3 gap-1.5 text-sm transition-colors font-mono text-[11px] ${bootstrapB64Copied ? '!border-green-500 !text-green-700' : '!border-orange-400 !text-orange-600 hover:!bg-orange-50'}`}
                      onClick={handleCopyBootstrapB64}
                      title="Copy base64 one-liner — paste directly into SSH terminal"
                    >
                      {bootstrapB64Copied ? <Check size={14} /> : <Copy size={14} />}
                      {bootstrapB64Copied ? 'Copied!' : 'base64'}
                    </button>
                  )}
                  {bootstrapScriptText && (
                    <button
                      className={`btn-outline h-10 px-3 gap-1.5 text-sm transition-colors ${bootstrapCopied ? '!border-green-500 !text-green-700' : ''}`}
                      onClick={handleCopyBootstrap}
                      title="Copy raw script text"
                    >
                      {bootstrapCopied ? <Check size={14} /> : <Copy size={14} />}
                      {bootstrapCopied ? 'Copied' : 'Script'}
                    </button>
                  )}
                  {bootstrapScriptText && (
                    <button
                      className={`btn-outline h-10 px-3 gap-1.5 text-sm transition-colors ${downloadedBootstrap ? '!border-green-500 !text-green-700' : ''}`}
                      onClick={handleDownloadBootstrap}
                      title="Save script to file"
                    >
                      {downloadedBootstrap ? <Check size={14} /> : <Download size={14} />}
                    </button>
                  )}
                </div>

                {bootstrapScriptText && bootstrapPlatform === 'sh' && (
                  <div className="mt-3 bg-gray-950 rounded-lg p-3 text-[11px] font-mono leading-relaxed space-y-1.5">
                    <div className="text-gray-400"># SSH one-liner — paste into any terminal, no file transfer needed:</div>
                    <div
                      className="text-orange-300 break-all cursor-pointer hover:text-orange-200 transition-colors"
                      onClick={handleCopyBootstrapB64}
                      title="Click to copy"
                    >
                      {`echo "${btoa(unescape(encodeURIComponent(bootstrapScriptText)))}" | base64 -d | bash`}
                    </div>
                    {collectionMode !== 'live' && (
                      <div className="text-gray-500 pt-1">
                        # {collectionMode === 'path' ? `path: ${collectionPath || '…'}` : `disk: ${collectionDisk || '…'}`}{bitlockerKey ? ' + BitLocker key' : ''} — all baked in config.json
                      </div>
                    )}
                  </div>
                )}

                {bootstrapScriptText && bootstrapPlatform === 'ps1' && (
                  <div className="mt-3 bg-gray-950 rounded-lg p-3 text-[11px] font-mono leading-relaxed space-y-1.5">
                    <div className="text-gray-500"># Run on Windows as Administrator:</div>
                    <div className="text-green-400">powershell -ExecutionPolicy Bypass -File fo-bootstrap-*.ps1</div>
                    <div className="text-gray-500 pt-1"># Flags: -Local (save locally), -NoCleanup (keep temp)</div>
                  </div>
                )}
              </div>
            )}

          </div>
        )}

        {/* ── Navigation ────────────────────────────────────────────── */}
        <div className="flex items-center justify-between mt-6">
          <button
            className="btn-outline gap-1"
            onClick={() => step > 1 && setStep(s => s - 1)}
            disabled={step === 1}
          >
            <ChevronLeft size={14} /> Back
          </button>
          {step < 3 && (
            <button
              className="btn-primary gap-1"
              onClick={() => setStep(s => s + 1)}
              disabled={step === 1 && platIdx === null}
            >
              Continue <ChevronRight size={14} />
            </button>
          )}
        </div>


      </div>
    </div>
  )
}

function SummaryRow({ label, value, mono }) {
  return (
    <div className="flex items-baseline gap-2 text-sm">
      <span className="text-gray-500 text-xs w-20 flex-shrink-0">{label}</span>
      <span className={`text-brand-text ${mono ? 'font-mono text-xs' : ''}`}>{value}</span>
    </div>
  )
}

