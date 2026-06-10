/**
 * Docs — platform documentation.
 *
 * Structured reference for:
 *   1. Architecture overview
 *   2. Creating custom ingesters
 *   3. Creating custom modules
 *   4. Writing alert rules
 *   5. API reference
 */
import { useState } from 'react'
import {
  BookOpen, Puzzle, Cpu, Bell, Server, ChevronRight,
  Code2, Copy, Check, AlertCircle, CheckCircle, Zap,
  FileCode2, Database, GitBranch, Terminal, PackageOpen,
} from 'lucide-react'

// ── Code block ────────────────────────────────────────────────────────────────

function CodeBlock({ code, language = 'python' }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div className="relative group rounded-xl overflow-hidden border border-gray-800 my-4">
      <div className="flex items-center justify-between bg-gray-900 px-4 py-2 border-b border-gray-800">
        <span className="text-[10px] text-gray-500 font-mono uppercase tracking-wider">{language}</span>
        <button
          onClick={copy}
          className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-gray-700 transition-colors"
        >
          {copied ? <><Check size={10} className="text-green-400" /> Copied</> : <><Copy size={10} /> Copy</>}
        </button>
      </div>
      <pre className="bg-gray-950 text-gray-200 font-mono text-[12px] leading-relaxed p-4 overflow-x-auto">
        {code}
      </pre>
    </div>
  )
}

// ── Info box ──────────────────────────────────────────────────────────────────

function InfoBox({ type = 'info', children }) {
  const styles = {
    info:    { cls: 'bg-blue-50 border-blue-200 text-blue-800', icon: <AlertCircle size={14} className="text-blue-500 flex-shrink-0 mt-0.5" /> },
    tip:     { cls: 'bg-green-50 border-green-200 text-green-800', icon: <CheckCircle size={14} className="text-green-500 flex-shrink-0 mt-0.5" /> },
    warning: { cls: 'bg-amber-50 border-amber-200 text-amber-800', icon: <AlertCircle size={14} className="text-amber-500 flex-shrink-0 mt-0.5" /> },
  }
  const s = styles[type] || styles.info
  return (
    <div className={`flex gap-2.5 border rounded-lg px-3.5 py-3 my-3 text-sm leading-relaxed ${s.cls}`}>
      {s.icon}
      <div>{children}</div>
    </div>
  )
}

// ── Section ───────────────────────────────────────────────────────────────────

function Section({ id, title, icon, children }) {
  return (
    <section id={id} className="mb-12 scroll-mt-4">
      <div className="flex items-center gap-2 mb-4 pb-2 border-b border-gray-200">
        <div className="w-7 h-7 rounded-lg bg-brand-accentlight border border-brand-accent/20 flex items-center justify-center flex-shrink-0">
          {icon}
        </div>
        <h2 className="text-base font-bold text-brand-text">{title}</h2>
      </div>
      <div className="prose-sm text-gray-700 space-y-3">
        {children}
      </div>
    </section>
  )
}

function H3({ children }) {
  return <h3 className="text-sm font-semibold text-gray-900 mt-5 mb-2">{children}</h3>
}

function P({ children }) {
  return <p className="text-sm text-gray-600 leading-relaxed">{children}</p>
}

function Li({ children }) {
  return (
    <li className="flex items-start gap-2 text-sm text-gray-600 leading-relaxed">
      <ChevronRight size={13} className="text-brand-accent flex-shrink-0 mt-0.5" />
      <span>{children}</span>
    </li>
  )
}

function Ul({ children }) {
  return <ul className="space-y-1.5 mt-1">{children}</ul>
}

function Field({ name, type, required, children }) {
  return (
    <div className="flex gap-3 py-2 border-b border-gray-100 last:border-0">
      <code className="text-[11px] font-mono text-brand-accent bg-brand-accentlight px-1.5 py-0.5 rounded flex-shrink-0 h-fit">
        {name}
      </code>
      <div className="min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-[10px] text-gray-500 font-mono">{type}</span>
          {required && (
            <span className="text-[10px] text-red-500 font-medium">required</span>
          )}
        </div>
        <p className="text-xs text-gray-500 leading-relaxed">{children}</p>
      </div>
    </div>
  )
}

// ── Navigation ────────────────────────────────────────────────────────────────

const SECTIONS = [
  { id: 'architecture', label: 'Architecture',        icon: <Server size={13} /> },
  { id: 'collector',    label: 'Artifact Collector',  icon: <PackageOpen size={13} /> },
  { id: 'ingesters',    label: 'Built-in Ingesters',  icon: <Puzzle size={13} /> },
  { id: 'custom-ingesters', label: 'Custom Ingesters', icon: <FileCode2 size={13} /> },
  { id: 'modules',      label: 'Modules',             icon: <Cpu size={13} /> },
  { id: 'alert-rules',  label: 'Alert Rules',         icon: <Bell size={13} /> },
  { id: 'query-syntax', label: 'Query Syntax',        icon: <Terminal size={13} /> },
  { id: 'search',       label: 'Investigation UI',    icon: <GitBranch size={13} /> },
  { id: 'api',          label: 'API Reference',       icon: <Code2 size={13} /> },
]

// ── Main ──────────────────────────────────────────────────────────────────────

export default function Docs() {
  const [active, setActive] = useState('architecture')

  function scrollTo(id) {
    setActive(id)
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="flex flex-1 overflow-hidden min-h-0">

      {/* Left nav */}
      <nav className="w-48 flex-shrink-0 flex flex-col border-r border-gray-200 bg-white overflow-y-auto">
        <div className="px-4 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <BookOpen size={15} className="text-brand-accent" />
            <span className="text-sm font-semibold text-brand-text">Documentation</span>
          </div>
        </div>
        <div className="flex-1 py-2">
          {SECTIONS.map(s => (
            <button
              key={s.id}
              onClick={() => scrollTo(s.id)}
              className={`w-full flex items-center gap-2 px-4 py-2 text-left text-xs transition-colors ${
                active === s.id
                  ? 'text-brand-accent bg-brand-accentlight font-medium'
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
              }`}
            >
              <span className="opacity-70">{s.icon}</span>
              {s.label}
            </button>
          ))}
        </div>
      </nav>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        <div className="px-6 py-6">

          {/* ── Architecture ──────────────────────────────────────────────── */}
          <Section id="architecture" title="Architecture Overview" icon={<Server size={14} className="text-brand-accent" />}>
            <P>
              Citadel is a containerised digital forensics platform. Evidence files are
              uploaded to MinIO, parsed by the Processor service, stored in Elasticsearch, and
              surfaced through the React frontend.
            </P>

            <H3>Services</H3>
            <div className="space-y-2">
              {[
                { name: 'api', port: '8000', desc: 'FastAPI — REST API, case management, rule library, editor' },
                { name: 'processor', port: 'worker', desc: 'Celery — ingest tasks, module runs, analysis jobs' },
                { name: 'elasticsearch', port: '9200', desc: 'Event storage and full-text search' },
                { name: 'redis', port: '6379', desc: 'Celery broker, job state, alert/module run metadata' },
                { name: 'minio', port: '9000/9001', desc: 'Object storage for uploaded evidence files' },
                { name: 'frontend', port: '3000', desc: 'React + Vite — web UI' },
              ].map(s => (
                <div key={s.name} className="flex gap-3 items-start py-1.5 border-b border-gray-100 last:border-0">
                  <code className="text-[11px] font-mono text-brand-accent bg-brand-accentlight px-1.5 py-0.5 rounded flex-shrink-0">
                    {s.name}
                  </code>
                  <span className="text-[10px] text-gray-500 font-mono flex-shrink-0 mt-0.5">:{s.port}</span>
                  <p className="text-xs text-gray-500">{s.desc}</p>
                </div>
              ))}
            </div>

            <H3>Data flow — ingest</H3>
            <CodeBlock language="text" code={`Upload file  →  POST /cases/{id}/ingest
                 →  MinIO  (raw file storage)
                 →  Celery ingest task
                 →  PluginLoader.get_plugin(filename, mime)
                 →  plugin.parse(file_path, context)  ← yields ParsedEvent objects
                 →  Elasticsearch  fo-case-{id}-{artifact_type} index`} />

            <H3>Data flow — module run</H3>
            <CodeBlock language="text" code={`Select module + source files  →  POST /cases/{id}/module-runs
                                    →  Redis run record  (PENDING)
                                    →  Celery module.run task
                                    →  download source files from MinIO → /tmp
                                    →  run built-in OR custom module
                                    →  upload results.json to MinIO
                                    →  update Redis run record  (COMPLETED + hits)`} />

            <H3>Custom extension points</H3>
            <Ul>
              <Li><strong>Custom Ingesters</strong> — files in <code className="text-brand-accent">ingester/*_ingester.py</code>, auto-loaded by PluginLoader alongside built-ins.</Li>
              <Li><strong>Custom Modules</strong> — files in <code className="text-brand-accent">modules/*_module.py</code>, dynamically loaded by the Celery worker at run time.</Li>
            </Ul>
            <InfoBox type="tip">
              Both directories are Docker volume-mounted and writable. Files you save via the <strong>Studio</strong> page are immediately available — no restart required.
            </InfoBox>
          </Section>

          {/* ── Collector ─────────────────────────────────────────────────── */}
          <Section id="collector" title="Artifact Collector" icon={<PackageOpen size={14} className="text-brand-accent" />}>
            <P>
              The <strong>Collector</strong> page generates a pre-configured Python harvester script (<code>fo-harvester.py</code>)
              that you run on a live system or against a mounted drive to collect forensic artifacts in a single ZIP.
              The ZIP is then uploaded to a case via <strong>Add Evidence</strong>.
            </P>

            <H3>Workflow</H3>
            <div className="space-y-2">
              {[
                { n: '1', label: 'Pick platform', desc: 'Select the OS of the evidence source — Windows, Linux, macOS, Android, or iOS. The generator tailors the artifact list and script syntax to the platform.' },
                { n: '2', label: 'Select artifacts', desc: 'Choose which artifact categories to collect (EVTX, registry, prefetch, browser data, …). Hover each item for a detailed description. Large items (AD database, Outlook PST) are flagged with a warning.' },
                { n: '3', label: 'Configure collection mode', desc: 'Live OS: run as Administrator/root directly on the target. Dead-box path: point at a mounted directory (--path). Dead-box disk: point at a raw device or drive letter (--disk). BitLocker recovery key can be supplied inline — it never touches the config.json.' },
                { n: '4', label: 'Auto-upload (optional)', desc: 'Configure the script to upload results directly to Citadel or to an S3 bucket. If disabled, the output ZIP is written to ./output/ for manual transfer.' },
                { n: '5', label: 'Download & run', desc: 'Download the harvester bundle (script + config.json). Transfer to the target and execute with Python 3.8+. The ZIP is created in ./output/ and can be uploaded to any case.' },
              ].map(({ n, label, desc }) => (
                <div key={n} className="flex gap-3 py-2 border-b border-gray-100 last:border-0">
                  <div className="w-5 h-5 rounded-full bg-brand-accent text-white flex items-center justify-center text-[10px] font-bold flex-shrink-0 mt-0.5">{n}</div>
                  <div>
                    <p className="text-xs font-semibold text-brand-text">{label}</p>
                    <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{desc}</p>
                  </div>
                </div>
              ))}
            </div>

            <H3>Collection modes</H3>
            <CodeBlock language="bash" code={`# Live Windows (run as Administrator):
python fo-harvester.py

# Dead-box — mounted Windows drive:
python fo-harvester.py --path D:\\

# Dead-box — raw disk image with BitLocker:
python fo-harvester.py --path E:\\ --bitlocker-key 123456-123456-123456-123456-123456-123456-123456-123456

# Linux — live system (run as root):
python3 fo-harvester.py

# Linux — mounted filesystem:
python3 fo-harvester.py --path /mnt/windows`} />

            <InfoBox type="tip">
              The BitLocker recovery key is passed at runtime and is <strong>never written to config.json</strong> — safe to run on shared infrastructure.
            </InfoBox>

            <H3>Auto-upload modes</H3>
            <div className="space-y-2">
              {[
                { label: 'None (default)', desc: 'ZIP written to ./output/ for manual upload via Case → Add Evidence.' },
                { label: 'Citadel', desc: 'Script uploads directly to the configured Citadel API endpoint and the case you specify. Requires network access from the target.' },
                { label: 'S3', desc: 'Script uploads to an S3-compatible bucket (MinIO, AWS S3, etc.). Useful for air-gapped collection hubs.' },
              ].map(({ label, desc }) => (
                <div key={label} className="flex gap-3 py-1.5 border-b border-gray-100 last:border-0">
                  <code className="text-[11px] font-mono text-brand-accent bg-brand-accentlight px-1.5 py-0.5 rounded flex-shrink-0 h-fit">{label}</code>
                  <p className="text-xs text-gray-500">{desc}</p>
                </div>
              ))}
            </div>

            <InfoBox type="info">
              The harvester requires only Python 3.8+ standard library on Windows. On Linux/macOS, no extra packages are needed for most artifacts. Memory acquisition additionally requires <code>winpmem</code> (Windows) or <code>avml</code> / <code>LiME</code> (Linux).
            </InfoBox>
          </Section>

          {/* ── Built-in Ingesters ────────────────────────────────────────── */}
          <Section id="ingesters" title="Built-in Ingesters" icon={<Puzzle size={14} className="text-brand-accent" />}>
            <P>
              Every uploaded file is matched against the built-in ingester registry. The first matching
              ingester runs and yields events into the case timeline. Matching is by file extension,
              exact filename, or MIME type — checked in that order.
            </P>

            <H3>Supported artifact types</H3>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <div className="bg-gray-50 px-4 py-2 border-b border-gray-200 grid grid-cols-3 gap-2">
                <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">artifact_type</span>
                <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Extensions / filenames</span>
                <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">What it parses</span>
              </div>
              <div className="divide-y divide-gray-100">
                {[
                  { type: 'evtx',          ext: '.evtx',                      desc: 'Windows Event Log — Security, System, Application, Sysmon, PowerShell' },
                  { type: 'hayabusa',      ext: '.jsonl / .csv',              desc: 'Hayabusa pre-analysed output (sigma-rule detection results)' },
                  { type: 'mft',           ext: '$MFT',                       desc: 'NTFS Master File Table — full filesystem timeline' },
                  { type: 'prefetch',      ext: '.pf',                        desc: 'Windows Prefetch — program execution history' },
                  { type: 'registry',      ext: 'SYSTEM/SOFTWARE/SAM/NTUSER.DAT', desc: 'Windows Registry hives' },
                  { type: 'lnk',           ext: '.lnk',                       desc: 'Shell link files — recent document / lateral movement evidence' },
                  { type: 'browser',       ext: 'History / Login Data / …',   desc: 'Chrome, Edge, Firefox, Brave SQLite databases' },
                  { type: 'access_log',    ext: '.log (Apache/Nginx)',        desc: 'Combined Log Format web server access logs' },
                  { type: 'suricata',      ext: 'eve.json',                   desc: 'Suricata NDJSON EVE log (alerts, flows, DNS, HTTP, TLS, …)' },
                  { type: 'zeek',          ext: '*.log (Zeek)',               desc: 'Zeek/Bro network logs (conn, dns, http, ssl, files, …)' },
                  { type: 'pcap',          ext: '.pcap / .pcapng',            desc: 'Packet capture — flows, DNS, HTTP extracted via dpkt/scapy' },
                  { type: 'syslog',        ext: '.log / syslog / auth.log',   desc: 'Generic syslog format (RFC 3164 / RFC 5424)' },
                  { type: 'auditd',        ext: 'audit.log',                  desc: 'Linux auditd kernel audit records' },
                  { type: 'scheduled_task', ext: '.xml (Tasks)',              desc: 'Windows Scheduled Task XML files' },
                  { type: 'wer',           ext: '.wer / .hdmp',               desc: 'Windows Error Reporting crash metadata' },
                  { type: 'dd_file',       ext: '.dd / .raw / .img',          desc: 'Raw disk image — NTFS/FAT filesystem walk + child ingest' },
                  { type: 'plaso',         ext: '.plaso',                     desc: 'Plaso super-timeline (L2T format)' },
                  { type: 'android',       ext: '.ab',                        desc: 'Android backup — apps, SMS, call log, contacts' },
                  { type: 'ios',           ext: 'iOS backup directory',       desc: 'iOS backup — Health, Messages, calls, photos metadata' },
                  { type: 'plist',         ext: '.plist',                     desc: 'macOS/iOS property list — preferences and system metadata' },
                  { type: 'shell_history', ext: '.bash_history / .zsh_history', desc: 'Shell command history files' },
                  { type: 'docker_event',  ext: 'docker*.log / docker*.json', desc: 'Docker daemon container lifecycle events' },
                  { type: 'k8s_event',     ext: 'k3s*.log',                   desc: 'Kubernetes / k3s API server and node events' },
                  { type: 'ndjson',        ext: '.ndjson / .jsonl',           desc: 'Generic NDJSON — each line a JSON event object' },
                ].map(({ type, ext, desc }) => (
                  <div key={type} className="px-4 py-2 grid grid-cols-3 gap-2 items-start hover:bg-gray-50/60">
                    <code className="text-[11px] font-mono text-brand-accent bg-brand-accentlight px-1.5 py-0.5 rounded self-start">{type}</code>
                    <span className="text-[11px] font-mono text-gray-500 leading-snug">{ext}</span>
                    <span className="text-xs text-gray-600 leading-snug">{desc}</span>
                  </div>
                ))}
              </div>
            </div>

            <InfoBox type="tip">
              Use <code>artifact_type:evtx</code> (or any type above) in the Timeline search bar to restrict
              results to that ingester. The <strong>Ingesters</strong> page shows all currently loaded plugins
              and lets you upload or write custom ones.
            </InfoBox>
          </Section>

          {/* ── Custom Ingesters ──────────────────────────────────────────── */}
          <Section id="custom-ingesters" title="Creating a Custom Ingester" icon={<FileCode2 size={14} className="text-brand-accent" />}>
            <P>
              An ingester is a Python class that parses an uploaded file into timeline events.
              Create one via <strong>Studio → Ingesters → New Ingester</strong>, or drop a
              file into <code className="text-gray-600">ingester/</code> at the repository root.
            </P>

            <InfoBox type="info">
              File name must end with <code>_ingester.py</code> and be placed in the
              <code> ingester/</code> directory.  The class must inherit from <code>BasePlugin</code>.
            </InfoBox>

            <H3>Minimal example</H3>
            <CodeBlock code={`from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

class ApacheAccessIngester(BasePlugin):
    PLUGIN_NAME          = "apache-access"
    SUPPORTED_EXTENSIONS = [".log"]
    HANDLED_FILENAMES    = ["access.log", "access_log"]

    def setup(self) -> None:
        if not self.ctx.source_file_path.exists():
            raise PluginFatalError("File not found")

    def parse(self):
        import re
        COMBINED = re.compile(
            r'(?P<host>\\S+) \\S+ \\S+ \\[(?P<time>[^\\]]+)\\] '
            r'"(?P<request>[^"]*)" (?P<status>\\d+) \\S+'
        )
        with open(self.ctx.source_file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = COMBINED.match(line.strip())
                if not m:
                    continue
                yield {
                    "timestamp":     self._parse_apache_time(m["time"]),
                    "message":       m["request"],
                    "artifact_type": self.PLUGIN_NAME,
                    "host":          {"hostname": m["host"]},
                    "extra":         {"status": int(m["status"])},
                }

    def _parse_apache_time(self, s: str) -> str:
        from datetime import datetime
        dt = datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()`} />

            <H3>BasePlugin reference</H3>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                <span className="text-xs font-semibold text-gray-600">Class attributes</span>
              </div>
              <div className="px-4">
                <Field name="PLUGIN_NAME" type="str" required>
                  Unique identifier. Used as <code>artifact_type</code> on every event and as the
                  Elasticsearch index name suffix: <code>fo-case-[case_id]-PLUGIN_NAME</code>.
                </Field>
                <Field name="SUPPORTED_EXTENSIONS" type="list[str]" required>
                  Lower-case extensions with leading dot, e.g. <code>[".log", ".txt"]</code>.
                  Leave empty to match by filename only.
                </Field>
                <Field name="HANDLED_FILENAMES" type="list[str]" required>
                  Exact filenames (case-insensitive) to match, e.g. <code>["$MFT", "NTUSER.DAT"]</code>.
                  Used for system files that have no extension.
                </Field>
              </div>
            </div>

            <H3>Event dict fields</H3>
            <P>
              Each <code>yield</code> produces a plain Python dict. Required keys:
            </P>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <div className="px-4">
                <Field name="timestamp" type="str" required>ISO-8601 UTC datetime, e.g. <code>2024-01-15T09:30:00Z</code>.</Field>
                <Field name="message" type="str" required>Human-readable description of the event.</Field>
                <Field name="artifact_type" type="str">Defaults to <code>PLUGIN_NAME</code>. Override to sub-categorise.</Field>
                <Field name="timestamp_desc" type="str">Label for what the timestamp represents, e.g. <code>"Last Modified"</code>.</Field>
                <Field name="host" type="dict">Host fields — <code>{"{"}"hostname": "...", "ip": "..."{"}"}. </code>Indexed under <code>host.*</code>.</Field>
                <Field name="user" type="dict">User fields — <code>{"{"}"name": "...", "domain": "..."{"}"}. </code>Indexed under <code>user.*</code>.</Field>
                <Field name="process" type="dict">Process fields — <code>{"{"}"name": "...", "pid": 123, "cmdline": "..."{"}"}.</code></Field>
                <Field name="network" type="dict">Network fields — <code>{"{"}"src_ip": "...", "dst_ip": "...", "dst_port": 443{"}"}.</code></Field>
                <Field name="extra" type="dict">Any additional fields. Stored under their own keys in Elasticsearch.</Field>
              </div>
            </div>

            <H3>Plugin lifecycle methods</H3>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <div className="px-4">
                <Field name="setup()" type="method">Called once before parsing. Open file handles or validate format here. Raise <code>PluginFatalError</code> to skip the file entirely.</Field>
                <Field name="parse()" type="method">Generator — yield one dict per event. Access the file via <code>self.ctx.source_file_path</code>.</Field>
                <Field name="teardown()" type="method">Called after parsing (always, even on error). Close file handles here.</Field>
                <Field name="get_stats()" type="method">Return a dict of plugin-specific stats shown in the job summary.</Field>
              </div>
            </div>

            <H3>After saving</H3>
            <P>
              Go to <strong>Ingesters → Reload All</strong> (or restart the processor container)
              to activate your new ingester. You can then upload a matching file in any case and
              it will be parsed automatically.
            </P>
          </Section>

          {/* ── Modules ───────────────────────────────────────────────────── */}
          <Section id="modules" title="Creating a Custom Module" icon={<Cpu size={14} className="text-brand-accent" />}>
            <P>
              A module is a Python file exposing a <code>run()</code> function that performs
              deeper analysis on files already stored in a case. Modules run as Celery tasks
              and produce their own results panel — separate from the event timeline.
            </P>

            <InfoBox type="info">
              File name must end with <code>_module.py</code> and be placed in the
              <code> modules/</code> directory.  No restart needed — the worker loads the file
              at task execution time.
            </InfoBox>

            <H3>Minimal example</H3>
            <CodeBlock code={`MODULE_NAME        = "String Extractor"
MODULE_DESCRIPTION = "Extract printable strings from any file"
INPUT_EXTENSIONS   = []   # empty = accept all files

import os
from pathlib import Path

def run(run_id, case_id, source_files, params,
        minio_client, redis_client, tmp_dir):

    min_len = int(params.get("min_length", 8))
    hits = []

    for sf in source_files:
        local = tmp_dir / sf["filename"]
        minio_client.fget_object(
            os.getenv("MINIO_BUCKET", "forensics-cases"),
            sf["minio_key"],
            str(local),
        )

        # Extract printable ASCII strings
        strings = _extract_strings(local, min_len)
        hits.extend({
            "filename": sf["filename"],
            "string":   s,
            "level":    "info",
        } for s in strings)

    return {"hits": hits, "total_hits": len(hits)}


def _extract_strings(path: Path, min_len: int):
    result, buf = [], []
    with open(path, "rb") as fh:
        for byte in fh.read():
            if 0x20 <= byte < 0x7F:
                buf.append(chr(byte))
            elif len(buf) >= min_len:
                result.append("".join(buf))
                buf = []
            else:
                buf = []
    return result`} />

            <H3>Module metadata</H3>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <div className="px-4">
                <Field name="MODULE_NAME" type="str" required>
                  Display name shown in the Modules selector, e.g. <code>"String Extractor"</code>.
                </Field>
                <Field name="MODULE_DESCRIPTION" type="str" required>Short description shown in the module card.</Field>
                <Field name="INPUT_EXTENSIONS" type="list[str]">
                  File extensions accepted as source input, e.g. <code>[".evtx", ".log"]</code>.
                  Leave empty to accept all files regardless of extension.
                </Field>
                <Field name="INPUT_FILENAMES" type="list[str]">
                  Exact filenames to match (like <code>HANDLED_FILENAMES</code> for ingesters).
                </Field>
              </div>
            </div>

            <H3>run() parameters</H3>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <div className="px-4">
                <Field name="run_id" type="str">Unique ID for this run — pass to Redis for status updates.</Field>
                <Field name="case_id" type="str">Case the module is running against.</Field>
                <Field name="source_files" type="list[dict]">
                  List of <code>{"{"}"job_id", "filename", "minio_key"{"}"}</code> dicts — the files selected by the user.
                </Field>
                <Field name="params" type="dict">User-supplied parameters (arbitrary key/value pairs).</Field>
                <Field name="minio_client" type="Minio">Configured MinIO client. Use <code>fget_object(bucket, key, local_path)</code> to download.</Field>
                <Field name="redis_client" type="Redis">Redis client (<code>decode_responses=True</code>). Useful for streaming progress updates.</Field>
                <Field name="tmp_dir" type="Path">Clean temporary directory. Deleted automatically after the run completes.</Field>
              </div>
            </div>

            <H3>Return value</H3>
            <CodeBlock code={`return {
    "hits": [
        {
            "filename": "Security.evtx",   # str — source file
            "level":    "high",            # critical | high | medium | low | info
            "message":  "...",             # description
            # add any extra fields you want shown in the results panel
        },
    ],
    "total_hits": 1,  # optional — computed from len(hits) if omitted
}`} />

            <H3>Module results in the Timeline</H3>
            <P>
              When a module run completes, its results are automatically indexed into Elasticsearch
              alongside regular ingester events. Each result becomes a searchable event with
              <code>artifact_type</code> set to the module's identifier.
            </P>
            <div className="space-y-1.5 mt-2">
              {[
                { mod: 'yara',               type: 'yara',           desc: 'YARA rule matches' },
                { mod: 'regripper',          type: 'regripper',      desc: 'Registry key analysis hits' },
                { mod: 'hayabusa (module)',  type: 'hayabusa',       desc: 'Sigma-rule EVTX detections' },
                { mod: 'wintriage',          type: 'wintriage',      desc: 'Windows triage analysis results' },
                { mod: 'volatility3',        type: 'volatility',     desc: 'Memory forensics artifacts' },
                { mod: 'ole_analysis',       type: 'oletools',       desc: 'OLE / VBA macro analysis' },
                { mod: 'pe_analysis',        type: 'pe_analysis',    desc: 'PE header and import analysis' },
                { mod: 'grep_search',        type: 'grep_search',    desc: 'Pattern search hits' },
                { mod: 'access_log_analysis',type: 'access_log',     desc: 'Web access log analysis' },
                { mod: 'browser_report',     type: 'browser',        desc: 'Browser history, downloads, logins' },
              ].map(({ mod, type, desc }) => (
                <div key={type} className="flex gap-3 items-center text-xs py-1 border-b border-gray-100 last:border-0">
                  <code className="font-mono text-brand-accent bg-brand-accentlight px-2 py-0.5 rounded text-[11px] flex-shrink-0 w-36">{type}</code>
                  <span className="text-gray-500 text-[11px] flex-shrink-0 w-36 italic">{mod}</span>
                  <span className="text-gray-600">{desc}</span>
                </div>
              ))}
            </div>
            <InfoBox type="tip">
              In the Module Runs panel, click <strong>Search in Timeline</strong> on any completed run to
              jump directly to the Timeline pre-filtered to that module's <code>artifact_type</code>.
              Custom modules not in the table above use their <code>module_id</code> (underscores, lowercase) as the <code>artifact_type</code>.
            </InfoBox>
          </Section>

          {/* ── Alert Rules ───────────────────────────────────────────────── */}
          <Section id="alert-rules" title="Alert Rules" icon={<Bell size={14} className="text-brand-accent" />}>
            <P>
              Alert rules are Elasticsearch query_string queries stored in the global library.
              Run them against any case from the <strong>Alert Rules</strong> page or from
              within a case using the <strong>Run Alerts</strong> button.
            </P>

            <H3>Rule fields</H3>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <div className="px-4">
                <Field name="name" type="str" required>Short, descriptive name shown in the rule list.</Field>
                <Field name="description" type="str">Explanation of what the rule detects and why it matters.</Field>
                <Field name="artifact_type" type="str">
                  Restrict the rule to a specific index, e.g. <code>evtx</code>, <code>suricata</code>.
                  Leave empty to search all indexes for the case.
                </Field>
                <Field name="query" type="str" required>
                  Lucene query_string syntax. See the Query Syntax section below.
                </Field>
                <Field name="threshold" type="int">
                  Minimum number of matching events to consider the rule "fired". Default: 1.
                </Field>
              </div>
            </div>

            <H3>Example rules</H3>
            <CodeBlock language="lucene" code={`# Event Log cleared (Security + System)
evtx.event_id:1102 OR evtx.event_id:104

# Brute-force (> 10 failures)
evtx.event_id:4625
threshold: 10

# PowerShell encoded command
evtx.event_id:4104 AND message:*-enc*

# Suricata malware category
suricata.event_type:alert AND message:*ET\\ MALWARE*

# Process spawned by Office app
evtx.event_id:4688 AND (message:*winword* OR message:*excel*)`} />

            <InfoBox type="tip">
              Use <strong>Load Default Rules</strong> to seed the built-in detection library.
              Rules are global — they apply to every case you run them against.
            </InfoBox>
          </Section>

          {/* ── Query Syntax ──────────────────────────────────────────────── */}
          <Section id="query-syntax" title="Query Syntax" icon={<Terminal size={14} className="text-brand-accent" />}>
            <P>
              The Timeline and Alert Rules use Elasticsearch <strong>Lucene query_string</strong> syntax.
              The search bar targets <code>message</code>, <code>host.hostname</code>, <code>user.name</code>,
              <code>process.name</code>, <code>process.cmdline</code>, and <code>process.args</code> by default.
              Prefix a term with a field name to search elsewhere.
            </P>

            <H3>Common patterns</H3>
            <div className="space-y-2">
              {[
                { q: 'evtx.event_id:4625',             desc: 'Field equals value' },
                { q: 'evtx.event_id:(4625 OR 4771)',   desc: 'OR group — failed auth' },
                { q: 'evtx.event_id:4688 AND message:*powershell*', desc: 'AND with wildcard' },
                { q: 'message:*encoded*',              desc: 'Wildcard (*) — any characters' },
                { q: 'NOT evtx.event_id:4672',         desc: 'NOT operator' },
                { q: 'evtx.event_id:[4600 TO 4700]',   desc: 'Range query' },
                { q: 'artifact_type:prefetch',         desc: 'Filter by ingester type' },
                { q: 'host.hostname:DESKTOP-*',        desc: 'Prefix match with wildcard' },
                { q: 'is_flagged:true',                desc: 'Only analyst-flagged events' },
                { q: 'tags:lateral-movement',          desc: 'Events with a specific tag' },
              ].map(r => (
                <div key={r.q} className="flex gap-3 items-start text-xs py-1.5 border-b border-gray-100 last:border-0">
                  <code className="font-mono text-brand-accent bg-brand-accentlight px-2 py-0.5 rounded text-[11px] flex-shrink-0">
                    {r.q}
                  </code>
                  <span className="text-gray-500 pt-0.5">{r.desc}</span>
                </div>
              ))}
            </div>

            <H3>Regexp mode</H3>
            <P>
              Enable the <strong>.*</strong> toggle in the search bar to match full event messages using
              Elasticsearch regexp syntax. This runs against the raw unanalyzed <code>message</code> field.
            </P>
            <InfoBox type="warning">
              ES regexp supports <code>. .* [a-z] (a|b) a+ a? a&#123;n,m&#125;</code> but <strong>NOT</strong>{' '}
              <code>\d \w \s</code>. Use <code>[0-9]</code>, <code>[a-zA-Z_]</code>, <code>[ \t]</code> instead.
            </InfoBox>
            <div className="space-y-2">
              {[
                { q: 'lateral.*movement',    desc: 'Any chars between words' },
                { q: 'cmd\\.exe',            desc: 'Escape literal dot' },
                { q: '4[6-9][0-9]{2}',       desc: 'Event ID range 4600-4999' },
                { q: '(mimikatz|sekurlsa)',   desc: 'Either word' },
              ].map(r => (
                <div key={r.q} className="flex gap-3 items-start text-xs py-1.5 border-b border-gray-100 last:border-0">
                  <code className="font-mono text-brand-accent bg-brand-accentlight px-2 py-0.5 rounded text-[11px] flex-shrink-0">
                    {r.q}
                  </code>
                  <span className="text-gray-500 pt-0.5">{r.desc}</span>
                </div>
              ))}
            </div>

            <H3>Indexed fields</H3>
            <Ul>
              <Li><code className="text-gray-600">timestamp</code> — ISO-8601 event time</Li>
              <Li><code className="text-gray-600">message</code> — human-readable description (full-text + keyword)</Li>
              <Li><code className="text-gray-600">artifact_type</code> — ingester that produced the event (evtx, prefetch, mft, registry, lnk, syslog, hayabusa, …)</Li>
              <Li><code className="text-gray-600">fo_id</code> — unique event ID</Li>
              <Li><code className="text-gray-600">host.*</code> — hostname, ip, os</Li>
              <Li><code className="text-gray-600">user.*</code> — name, domain, sid</Li>
              <Li><code className="text-gray-600">process.*</code> — name, pid, cmdline, args, path</Li>
              <Li><code className="text-gray-600">network.*</code> — src_ip, dst_ip, dst_port, protocol</Li>
              <Li><code className="text-gray-600">evtx.*</code> — event_id, channel, provider_name</Li>
              <Li><code className="text-gray-600">registry.*</code> — key_path, value_name, value_data</Li>
              <Li><code className="text-gray-600">prefetch.*</code> — executable, run_count, last_run</Li>
              <Li><code className="text-gray-600">lnk.*</code> — target_path, machine_id</Li>
              <Li><code className="text-gray-600">hayabusa.*</code> — level, rule_title</Li>
              <Li><code className="text-gray-600">is_flagged</code>, <code className="text-gray-600">tags</code>, <code className="text-gray-600">analyst_note</code> — analyst annotations</Li>
            </Ul>

            <InfoBox type="tip">
              Fields from the <code>extra</code> dict in custom ingesters are stored at the top level —
              search them directly by their key name. Use AI Search Assist (✦ button) to generate queries
              from plain English.
            </InfoBox>
          </Section>

          {/* ── Investigation UI ──────────────────────────────────────────── */}
          <Section id="search" title="Investigation UI" icon={<GitBranch size={14} className="text-brand-accent" />}>
            <P>
              The <strong>Timeline</strong> tab is the unified investigation workspace. It combines
              chronological event browsing, full-text search, facet filtering, saved searches, date
              range navigation, and AI-assisted query generation in a single view.
            </P>

            <H3>Search bar</H3>
            <Ul>
              <Li>Press <kbd className="px-1 bg-gray-100 rounded text-[10px] font-mono">/</kbd> to focus the search bar from anywhere on the page</Li>
              <Li>Press <strong>Enter</strong> or click <strong>Search</strong> to apply the query</Li>
              <Li>Toggle <strong>.*</strong> to switch to ES regexp mode — matches against the full raw message string. Use this for patterns like <code>cmd\.exe</code> or <code>4[6-9][0-9]&#123;2&#125;</code></Li>
              <Li>Click <strong>✦</strong> (Sparkles) to open AI Search Assist — describe what you want to find in plain English and the AI generates the query</Li>
            </Ul>

            <InfoBox type="tip">
              Use normal query_string mode for field-level queries (<code>evtx.event_id:4625</code>) and bare-term searches.
              Switch to regexp mode only when you need to match a pattern across the full message text — it is slower on large datasets.
            </InfoBox>

            <H3>Date range & histogram</H3>
            <Ul>
              <Li>Use the <strong>From / To</strong> date pickers in the left sidebar to restrict events to a time window</Li>
              <Li>Click a <strong>date preset</strong> (Last 24h, 7d, 30d, 90d) for quick ranges</Li>
              <Li>The <strong>event histogram</strong> shows event count per day for the current filter — click a bar to jump to that date</Li>
            </Ul>

            <H3>Facet filter chips</H3>
            <P>
              The left sidebar shows <strong>Host</strong>, <strong>User</strong>, <strong>Event ID</strong>, and <strong>Channel</strong>
              facet chips auto-computed from the current result set. Click a chip to add it as an exclusive filter —
              click again to remove. Multiple facets can be active simultaneously.
              Active filters appear as dismissible badges below the search bar alongside a <strong>Clear all</strong> button.
            </P>

            <H3>Saved searches</H3>
            <P>
              When a query or facet filter is active, click <strong>+ Save</strong> in the sidebar to
              name and persist the search for the current case. Saved searches restore both the query
              text and any active facet filters. Hover a saved search and click the trash icon to delete it.
            </P>

            <H3>Column picker</H3>
            <P>
              Click the <strong>Columns</strong> button (top-right of the results table) to toggle which
              fields are shown: Timestamp, Type, Host, User, Process, Message, Source, Tags, Note.
              Column visibility is saved to localStorage per browser session.
            </P>

            <H3>Sorting</H3>
            <P>
              Click any sortable column header (Timestamp, Type, Host, User) to sort by that field.
              An arrow indicator shows the active sort direction. Click again to reverse. Default is
              timestamp ascending (oldest first) so the attack chain reads chronologically.
            </P>

            <H3>Event detail panel</H3>
            <P>
              Click any row to open the full event detail panel on the right. From there you can:
            </P>
            <Ul>
              <Li><strong>Flag</strong> the event for follow-up (bookmark icon) — flagged events are searchable with <code>is_flagged:true</code></Li>
              <Li><strong>Tag</strong> the event with investigator labels (e.g. <code>lateral-movement</code>, <code>c2</code>)</Li>
              <Li><strong>Add a note</strong> — free-text analyst annotation stored alongside the event</Li>
              <Li><strong>AI Explain</strong> — sends the event to the configured LLM for a forensic significance summary</Li>
              <Li>Click any field value to add it as an inline query filter (<code>AND field:"value"</code>)</Li>
            </Ul>

            <H3>Keyboard shortcuts</H3>
            <div className="space-y-1 mt-2">
              {[
                { key: '/',          desc: 'Focus search bar' },
                { key: '?',          desc: 'Toggle keyboard shortcut help overlay' },
                { key: '↑ / ↓',      desc: 'Navigate rows (when search bar is not focused)' },
                { key: 'Enter',      desc: 'Open detail panel for the selected row' },
                { key: 'Escape',     desc: 'Close detail panel / blur search bar' },
              ].map(r => (
                <div key={r.key} className="flex gap-3 items-center text-xs py-1 border-b border-gray-100 last:border-0">
                  <kbd className="font-mono bg-gray-100 text-gray-700 px-2 py-0.5 rounded text-[11px] flex-shrink-0 min-w-[60px] text-center">{r.key}</kbd>
                  <span className="text-gray-500">{r.desc}</span>
                </div>
              ))}
            </div>

            <H3>Event deduplication</H3>
            <P>
              Events with identical timestamp, message, artifact type, host, and user are automatically
              deduplicated client-side. This prevents the same log entry from appearing twice when an
              artifact was ingested from multiple sources (e.g. raw EVTX + a Plaso super-timeline of
              the same disk image).
            </P>

            <H3>AI Search Assist</H3>
            <P>
              The <strong>✦</strong> button next to the search bar opens an input where you describe what
              you want to find in plain English. The configured LLM (Settings → AI Analysis) translates it
              into an Elasticsearch query_string aware of the full field schema — EVTX event IDs, registry
              paths, prefetch fields, Hayabusa rule levels, MFT attributes, and common attack patterns
              (lateral movement, credential dumping, persistence, log tampering, …).
            </P>
            <P>
              The AI also knows when to suggest regexp mode — for example, if you ask for
              "events matching the pattern 4[6-9]xx" it will set regexp mode automatically.
            </P>
            <InfoBox type="info">
              AI Assist requires an LLM configured in Settings → AI Analysis. The generated query is
              pre-filled in the search bar and editable before you execute — always review before
              running against large datasets.
            </InfoBox>
          </Section>

          {/* ── API Reference ─────────────────────────────────────────────── */}
          <Section id="api" title="API Reference" icon={<Code2 size={14} className="text-brand-accent" />}>
            <P>
              The REST API is served at <code>http://localhost:8000/api/v1</code>.
              Interactive docs: <a href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer"
                className="text-brand-accent hover:underline">localhost:8000/docs</a> (Swagger UI).
            </P>

            <H3>Cases</H3>
            <CodeBlock language="http" code={`GET    /cases                            list all cases
POST   /cases                            create case  {name, description?}
GET    /cases/{id}                       get case
DELETE /cases/{id}                       delete case

POST   /cases/{id}/ingest                upload evidence file (multipart)
GET    /cases/{id}/jobs                  list ingest jobs
GET    /jobs/{job_id}                    get single job`} />

            <H3>Search</H3>
            <CodeBlock language="http" code={`GET /cases/{id}/timeline     timeline events  ?from=&to=&artifact=&page=
GET /cases/{id}/search       free-text search ?q=&page=&per_page=
GET /cases/{id}/search/facets           field facets for filters`} />

            <H3>Modules</H3>
            <CodeBlock language="http" code={`GET    /modules                          list all modules (built-in + custom)
GET    /cases/{id}/sources               source files available for a case
                                           fast path: queries fo-artifacts ES index
                                           fallback: Redis sorted-set scan (5 000 cap)
POST   /cases/{id}/module-runs           launch a module run  {module_id, job_ids[]}
GET    /cases/{id}/module-runs           list runs for a case
GET    /module-runs/{run_id}             get run with full results_preview
GET    /module-runs/{run_id}/log-stream  SSE stream of live log lines (text/event-stream)
                                           each event: {text: str}  final: {done: true, status}
POST   /modules/yara/validate            validate YARA rule syntax  {rules}`} />

            <H3>Studio (rule playground &amp; testers)</H3>
            <CodeBlock language="http" code={`POST /studio/query-test   {case_id, query}
  → {hits: [...]}  — first 10 events matching the Lucene query
    use in Studio → alert-rule editor → "Test Query" button

POST /studio/yara-test    {case_id, job_id, rules}
  → {matches: [{rule, tags, strings[{identifier, offset}]}], scanned_bytes}
    scans up to 10 MB of the selected source file
    use in Studio → YARA editor → "Test YARA" button`} />

            <H3>Alert Rules</H3>
            <CodeBlock language="http" code={`GET    /alert-rules/library              list global rule library
POST   /alert-rules/library              create rule
PUT    /alert-rules/library/{id}         update rule
DELETE /alert-rules/library/{id}         delete rule
POST   /alert-rules/library/seed         seed default rules  ?replace=false
POST   /cases/{id}/alert-rules/run-library   run all rules against case
POST   /cases/{id}/alert-rules/library/{rule_id}/run  run single rule`} />

            <H3>Editor (Studio)</H3>
            <CodeBlock language="http" code={`GET    /editor/ingesters                 list ingester files
GET    /editor/ingesters/{name}          read file
PUT    /editor/ingesters/{name}          write file  {content}
DELETE /editor/ingesters/{name}          delete file

GET    /editor/modules                   list module files
GET    /editor/modules/{name}            read file
PUT    /editor/modules/{name}            write file  {content}
DELETE /editor/modules/{name}            delete file

POST   /editor/validate                  Python syntax check  {code}`} />

            <H3>Plugins (ingesters — loaded)</H3>
            <CodeBlock language="http" code={`GET  /plugins        list loaded plugin classes
POST /plugins/reload  reload plugin directory
POST /plugins/upload  upload a .py file (multipart)`} />
          </Section>

        </div>
      </div>
    </div>
  )
}
