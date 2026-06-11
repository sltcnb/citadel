/**
 * Studio — in-browser code editor for custom ingesters, modules,
 * YARA rules, and alert rules.
 *
 * Supports VS Code-style multi-file tabs with independent dirty state per tab.
 *
 * Ingesters   → ingester/*_ingester.py  — BasePlugin subclasses
 * Modules     → modules/*_module.py     — standalone run(run_id, …) functions
 * YARA Rules  → stored in Redis / YARA library
 * Alert Rules → stored in Redis / global alert-rule library (Sigma or custom YAML)
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import { useLocation } from 'react-router-dom'
import {
  Code2, Plus, Save, Trash2, CheckCircle, AlertCircle,
  RefreshCw, FileCode2, X, ChevronRight, Cpu, Puzzle,
  Play, BookOpen, Copy, Check, Lock, Shield, Bell, Pencil,
  Terminal, Zap, Database, FileText, Braces, Search,
  ChevronDown, LayoutTemplate,
} from 'lucide-react'
import Editor from '@monaco-editor/react'
import { api, getToken } from '../api/client'
import RuleDrawer, {
  CategoryBadge, SigmaLevelBadge,
  CATEGORY_ORDER, CATEGORY_STYLES,
} from '../components/RuleDrawer'
import YaraRuleModal from '../components/YaraRuleModal'
import { ProvenancePills } from '../components/AlertRuleFilterBar'
import { filterAlertRules } from '../lib/alertRuleFilters'

// ── Templates ─────────────────────────────────────────────────────────────────

const INGESTER_TEMPLATE = (name = 'my_format') => {
  const cls = name.replace(/(^|_)([a-z])/g, (_, _p, c) => c.toUpperCase())
  return `"""
${name}_ingester.py — custom ingester for ${name.replace(/_/g, ' ')} artifacts.

Naming rules:
  • File must end with _ingester.py
  • PLUGIN_NAME must be unique across all plugins

Plugin lifecycle:
  1. can_handle(path, mime) → True / False
  2. setup()    — validate / open the file
  3. parse()    — yield one dict per event
  4. teardown() — release resources (always called)
"""
from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError


class ${cls}Ingester(BasePlugin):
    PLUGIN_NAME = "${name.replace(/_/g, '-')}"

    # Lower-case extensions with leading dot
    SUPPORTED_EXTENSIONS = [".log", ".txt"]

    # Exact filenames matched case-insensitively (no extension needed)
    HANDLED_FILENAMES = []  # e.g. ["$MFT", "NTUSER.DAT"]

    def setup(self) -> None:
        """Validate the file. Raise PluginFatalError to skip this file."""
        if not self.ctx.source_file_path.exists():
            raise PluginFatalError(f"File not found: {self.ctx.source_file_path}")

    def parse(self):
        """
        Generator — yield one dict per event.

        Required keys:
            timestamp  str   ISO-8601 UTC, e.g. "2024-01-15T10:23:45Z"
            message    str   human-readable summary

        Optional keys:
            artifact_type  str   overrides PLUGIN_NAME
            timestamp_desc str   label for what the timestamp represents
            host           dict  {"hostname": "DESKTOP-01"}
            user           dict  {"name": "alice", "domain": "CORP"}
            process        dict  {"name": "cmd.exe", "pid": 1234}
            extra          dict  any additional fields
        """
        src = self.ctx.source_file_path
        try:
            with open(src, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\\n")
                    if not line:
                        continue
                    yield {
                        "timestamp":     self._extract_timestamp(line),
                        "message":       line,
                        "artifact_type": self.PLUGIN_NAME,
                        # "host":    {"hostname": ""},
                        # "user":    {"name": ""},
                        # "extra":   {"key": "value"},
                    }
        except OSError as exc:
            raise PluginFatalError(f"Cannot read {src}: {exc}") from exc

    def _extract_timestamp(self, line: str) -> str:
        """Return ISO-8601 UTC timestamp parsed from line, or now() as fallback."""
        import re
        from datetime import datetime, timezone
        # TODO: adapt this regex to your actual log timestamp format
        m = re.match(r"(\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2})", line)
        if m:
            return m.group(1).replace(" ", "T") + "Z"
        return datetime.now(timezone.utc).isoformat()
`
}

const MODULE_TEMPLATE = (name = 'my_analysis') => `"""
${name}_module.py — custom analysis module: ${name.replace(/_/g, ' ')}.

Naming rules
  • File must end with _module.py
  • MODULE_NAME is displayed in the Modules panel
  • INPUT_EXTENSIONS filters which source files are shown when launching

Security model
  • Code runs in an isolated subprocess with resource limits:
      CPU: 3600s   Memory: 2 GB   File writes: 500 MB   Subprocesses: 64
  • Sensitive env vars are stripped before your code runs
  • tmp_dir is the only writable work area (cleaned up automatically)
"""
import re
import subprocess
from pathlib import Path

# ── Module metadata (read by the platform to populate the Modules list) ────────

MODULE_NAME        = "${name.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}"
MODULE_DESCRIPTION = "Custom analysis module — describe what it does here"

# File extensions this module accepts (lower-case, with dot). Leave empty for any.
INPUT_EXTENSIONS   = []
# Exact filenames to match regardless of extension (e.g. ["NTUSER.DAT", "$MFT"])
INPUT_FILENAMES    = []


# ── Entry point ────────────────────────────────────────────────────────────────

def run(
    run_id: str,
    case_id: str,
    source_files: list,
    params: dict,
    minio_client,       # minio.Minio — fget_object / put_object / etc.
    redis_client,       # redis.Redis (decode_responses=True)
    tmp_dir: Path,      # clean temp directory, wiped after the run
) -> list:
    """
    Execute the module and return a list of findings.

    Each finding dict must have at minimum:
      filename  str   — source file the finding came from
      message   str   — human-readable description
      level     str   — "critical" | "high" | "medium" | "low" | "info"
    Additional fields are stored and rendered in the results panel as-is.
    """
    MINIO_BUCKET = "forensics-cases"
    hits = []

    for sf in source_files:
        local_path = tmp_dir / sf["filename"]

        # ── Download source file from MinIO ────────────────────────────────────
        minio_client.fget_object(MINIO_BUCKET, sf["minio_key"], str(local_path))

        # ── Example: extract printable strings and flag suspicious patterns ────
        try:
            proc = subprocess.run(
                ["strings", "-n", "8", str(local_path)],
                capture_output=True, text=True, timeout=120,
            )
            strings_found = proc.stdout.splitlines()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Pure-Python fallback if 'strings' binary is unavailable
            with open(local_path, "rb") as fh:
                data = fh.read()
            strings_found = [
                s.decode("ascii", errors="replace")
                for s in re.findall(rb"[ -~]{8,}", data)
            ]

        # Flag patterns of interest — replace or extend this dict
        ioc_patterns = {
            r"(?i)powershell":               ("high",     "PowerShell reference"),
            r"(?i)mimikatz":                 ("critical", "Mimikatz reference"),
            r"(?i)cmd\\.exe":                ("medium",   "cmd.exe reference"),
            r"https?://[^\\s]{10,}":         ("medium",   "URL found"),
            r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b": ("low", "IP address found"),
        }

        for string in strings_found:
            for pattern, (level, label) in ioc_patterns.items():
                if re.search(pattern, string):
                    hits.append({
                        "filename": sf["filename"],
                        "level":    level,
                        "message":  f"{label}: {string[:200]}",
                        "string":   string[:500],
                    })

        # Limit to first 1000 hits per file
        hits = hits[:1000]

    return hits
`

const SIGMA_TEMPLATE = (name = 'My Rule') => `title: ${name}
id: ${crypto.randomUUID ? crypto.randomUUID() : ''}
status: experimental
description: Detect suspicious activity — describe here
author: analyst
date: ${new Date().toISOString().slice(0, 10)}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
        CommandLine|contains: 'suspicious'
    condition: selection
level: medium
tags:
    - attack.execution
falsepositives:
    - Legitimate use
`

const CUSTOM_RULE_TEMPLATE = (name = 'My Rule') => `# Custom alert rule (not Sigma)
# Edit the fields below and save to add to the library.
name: ${name}
description: Detect suspicious activity
category: General
artifact_type: evtx
query: evtx.event_id:4625
threshold: 1
`

// ── Helpers ───────────────────────────────────────────────────────────────────

function fileId(type, name) { return `${type}:${name}` }

// ── Type metadata ─────────────────────────────────────────────────────────────

const TYPE_BADGE = {
  ingester:  { letter: 'I', cls: 'bg-blue-100 text-blue-600' },
  module:    { letter: 'M', cls: 'bg-purple-100 text-purple-600' },
  alertrule: { letter: 'A', cls: 'bg-orange-100 text-orange-600' },
}

const TYPE_TOOLBAR = {
  ingester:  { label: 'ingester',   cls: 'bg-blue-50 text-blue-700 border border-blue-100' },
  module:    { label: 'module',     cls: 'bg-purple-50 text-purple-700 border border-purple-100' },
  alertrule: { label: 'detection rule', cls: 'bg-orange-50 text-orange-700 border border-orange-100' },
}

// ── Template catalog ──────────────────────────────────────────────────────────

const TEMPLATE_CATALOG = {
  ingester: [
    {
      id: 'quick',
      label: 'Quick (SDK)',
      desc: 'Minimal — just a parse(ctx) function, no class boilerplate',
      icon: Zap,
      color: 'text-green-500',
      build: (name) => `"""${name}_ingester.py — minimal parser via the authoring SDK.

Same BasePlugin contract under the hood, far less boilerplate. ctx gives
readers: ctx.lines() · ctx.text() · ctx.json() · ctx.jsonl() · ctx.raw_bytes().
event(...) builds a contract-compliant event.
"""
from citadel_contracts.sdk import parser, event


@parser(name="${name.replace(/_/g, '-')}", extensions=[".log"])
def parse(ctx):
    for line in ctx.lines():
        if not line.strip():
            continue
        # timestamp accepts ISO / epoch / datetime; it's canonicalized for you.
        yield event(timestamp=line[:19], message=line)
`,
    },
    {
      id: 'basic',
      label: 'Text Log (class)',
      desc: 'Full BasePlugin class — line-by-line log parser',
      icon: FileText,
      color: 'text-blue-500',
      build: INGESTER_TEMPLATE,
    },
    {
      id: 'csv',
      label: 'CSV / TSV',
      desc: 'DictReader-based CSV/TSV ingester',
      icon: Database,
      color: 'text-cyan-500',
      build: (name) => {
        const cls = name.replace(/(^|_)([a-z])/g, (_, _p, c) => c.toUpperCase())
        return `"""${name}_ingester.py — CSV/TSV ingester."""
from babel.base_plugin import BasePlugin, PluginFatalError
import csv


class ${cls}Ingester(BasePlugin):
    PLUGIN_NAME          = "${name.replace(/_/g, '-')}"
    SUPPORTED_EXTENSIONS = [".csv", ".tsv"]

    def setup(self):
        if not self.ctx.source_file_path.exists():
            raise PluginFatalError(f"File not found: {self.ctx.source_file_path}")

    def parse(self):
        sep = "\\t" if self.ctx.source_file_path.suffix.lower() == ".tsv" else ","
        with open(self.ctx.source_file_path, encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.DictReader(fh, delimiter=sep):
                yield {
                    "timestamp":     row.get("timestamp") or row.get("date") or row.get("time", ""),
                    "message":       str(row),
                    "artifact_type": self.PLUGIN_NAME,
                    "extra":         dict(row),
                }
`
      },
    },
    {
      id: 'jsonl',
      label: 'JSON / JSONL',
      desc: 'One JSON object per line (newline-delimited JSON)',
      icon: Braces,
      color: 'text-amber-500',
      build: (name) => {
        const cls = name.replace(/(^|_)([a-z])/g, (_, _p, c) => c.toUpperCase())
        return `"""${name}_ingester.py — JSONL ingester."""
import json
from babel.base_plugin import BasePlugin, PluginFatalError


class ${cls}Ingester(BasePlugin):
    PLUGIN_NAME          = "${name.replace(/_/g, '-')}"
    SUPPORTED_EXTENSIONS = [".json", ".jsonl", ".ndjson"]

    def setup(self):
        if not self.ctx.source_file_path.exists():
            raise PluginFatalError(f"File not found: {self.ctx.source_file_path}")

    def parse(self):
        with open(self.ctx.source_file_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield {
                    "timestamp":     obj.get("timestamp") or obj.get("ts") or obj.get("time", ""),
                    "message":       obj.get("message") or obj.get("msg") or str(obj)[:200],
                    "artifact_type": self.PLUGIN_NAME,
                    "extra":         obj,
                }
`
      },
    },
  ],
  module: [
    {
      id: 'strings',
      label: 'String Analysis',
      desc: 'Extract strings and flag suspicious patterns (default)',
      icon: Search,
      color: 'text-purple-500',
      build: MODULE_TEMPLATE,
    },
    {
      id: 'hash',
      label: 'Hash Lookup',
      desc: 'Compute MD5/SHA256 and check against known IOC lists',
      icon: Shield,
      color: 'text-red-500',
      build: (name) => {
        const display = name.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
        return `"""${name}_module.py — compute file hashes and flag known malicious hashes."""
import hashlib
from pathlib import Path

MODULE_NAME        = "${display}"
MODULE_DESCRIPTION = "Compute MD5 / SHA-256 for each source file and flag against a known-bad list"
INPUT_EXTENSIONS   = []
INPUT_FILENAMES    = []

# Add known-bad SHA-256 hashes here (lower-case)
KNOWN_BAD: set[str] = set()


def run(run_id, case_id, source_files, params, minio_client, redis_client, tmp_dir: Path):
    BUCKET = "forensics-cases"
    hits = []
    for sf in source_files:
        local = tmp_dir / sf["filename"]
        minio_client.fget_object(BUCKET, sf["minio_key"], str(local))
        data = local.read_bytes()
        md5    = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        level  = "critical" if sha256 in KNOWN_BAD else "info"
        hits.append({
            "filename": sf["filename"],
            "level":    level,
            "message":  f"MD5={md5}  SHA256={sha256}" + ("  ← KNOWN MALICIOUS" if level == "critical" else ""),
            "md5":      md5,
            "sha256":   sha256,
        })
    return hits
`
      },
    },
  ],
}

// ── NewFileModal ──────────────────────────────────────────────────────────────

function NewFileModal({ type, existing, onClose, onCreate }) {
  const templates = TEMPLATE_CATALOG[type] || []
  const [selectedTpl, setSelectedTpl] = useState(templates[0]?.id || '')
  const [name, setName] = useState('')

  const isCodeFile = type === 'ingester' || type === 'module'
  const suffix     = type === 'ingester' ? '_ingester' : type === 'module' ? '_module' : ''
  const ext        = isCodeFile ? '.py' : ''
  const chosenTpl  = templates.find(t => t.id === selectedTpl) || templates[0]

  const titles = { ingester: 'New Ingester', module: 'New Module', yara: 'New YARA Rule', alertrule: 'New Detection Rule' }
  const placeholders = { ingester: 'my_format', module: 'my_analysis', yara: 'DetectMimikatz', alertrule: 'Suspicious Login' }

  function handleCreate(e) {
    e.preventDefault()
    const trimmed = name.trim()
    if (!trimmed) return
    if (isCodeFile) {
      const slug = trimmed.toLowerCase().replace(/[^a-z0-9_]/g, '_')
      const full = `${slug}${suffix}${ext}`
      if (existing.includes(full)) { alert(`${full} already exists.`); return }
      onCreate(full, undefined, chosenTpl?.build)
    } else {
      onCreate(trimmed, chosenTpl?.ruleKind, chosenTpl?.build)
    }
    onClose()
  }

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-box max-w-xl">
        <div className="modal-header">
          <div className="flex items-center gap-2">
            <LayoutTemplate size={15} className="text-brand-accent" />
            <span className="text-sm font-semibold">{titles[type] || 'New File'}</span>
          </div>
          <button className="icon-btn" onClick={onClose}><X size={14} /></button>
        </div>

        <div className="p-5 space-y-4">
          {/* Template picker */}
          {templates.length > 1 && (
            <div>
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">Template</p>
              <div className="grid grid-cols-2 gap-2">
                {templates.map(tpl => {
                  const Icon = tpl.icon
                  const active = selectedTpl === tpl.id
                  return (
                    <button
                      key={tpl.id}
                      type="button"
                      onClick={() => setSelectedTpl(tpl.id)}
                      className={`flex items-start gap-3 p-3 rounded-lg border text-left transition-all ${
                        active
                          ? 'border-brand-accent bg-brand-soft/50 shadow-sm'
                          : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                      }`}
                    >
                      <Icon size={16} className={`flex-shrink-0 mt-0.5 ${active ? 'text-brand-accent' : tpl.color}`} />
                      <div>
                        <p className={`text-xs font-semibold ${active ? 'text-brand-accent' : 'text-gray-700'}`}>{tpl.label}</p>
                        <p className="text-[11px] text-gray-500 mt-0.5 leading-tight">{tpl.desc}</p>
                      </div>
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {/* Name */}
          <form onSubmit={handleCreate} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1.5">
                Name {isCodeFile && <span className="text-gray-500 font-normal">(letters, digits, underscores)</span>}
              </label>
              <div className="flex items-center gap-1">
                <input
                  autoFocus
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder={placeholders[type] || 'name'}
                  className="input flex-1"
                />
                {isCodeFile && (
                  <span className="text-xs text-gray-500 font-mono whitespace-nowrap">{suffix}{ext}</span>
                )}
              </div>
            </div>

            <div className="flex justify-end gap-2">
              <button type="button" className="btn-ghost text-sm" onClick={onClose}>Cancel</button>
              <button type="submit" className="btn-primary text-sm" disabled={!name.trim()}>Create</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}

// ── DeleteConfirmModal ────────────────────────────────────────────────────────

function DeleteConfirmModal({ file, onClose, onConfirm }) {
  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-box max-w-sm">
        <div className="modal-header">
          <span className="text-sm font-semibold text-red-600">Delete</span>
          <button className="icon-btn" onClick={onClose}><X size={14} /></button>
        </div>
        <div className="p-5 space-y-4">
          <p className="text-sm text-gray-600">
            Delete <code className="text-brand-accent font-mono">{file}</code>?
            This cannot be undone.
          </p>
          <div className="flex justify-end gap-2">
            <button className="btn-ghost text-sm" onClick={onClose}>Cancel</button>
            <button className="btn-danger text-sm" onClick={onConfirm}>Delete</button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── CodeEditor ────────────────────────────────────────────────────────────────

function detectLanguage(tab) {
  if (!tab) return 'plaintext'
  if (tab.type === 'yara')      return 'plaintext'  // no YARA grammar in Monaco by default
  if (tab.type === 'alertrule') return 'yaml'
  if (tab.name?.endsWith('.py')) return 'python'
  return 'python'
}

function CodeEditor({ value, onChange, readOnly = false, tab }) {
  const language = detectLanguage(tab)

  return (
    <Editor
      height="100%"
      language={language}
      value={value}
      onChange={v => !readOnly && onChange(v ?? '')}
      theme="vs-dark"
      options={{
        readOnly,
        fontSize: 13,
        fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", ui-monospace, Menlo, Monaco, Consolas, monospace',
        fontLigatures: true,
        minimap: { enabled: true },
        lineNumbers: 'on',
        glyphMargin: false,
        folding: true,
        wordWrap: 'on',
        tabSize: 4,
        insertSpaces: true,
        renderWhitespace: 'selection',
        scrollBeyondLastLine: false,
        automaticLayout: true,
        smoothScrolling: true,
        cursorBlinking: 'smooth',
        bracketPairColorization: { enabled: true },
        formatOnPaste: false,
        suggestOnTriggerCharacters: true,
        quickSuggestions: { other: true, comments: false, strings: false },
        acceptSuggestionOnEnter: 'smart',
        padding: { top: 12, bottom: 12 },
      }}
    />
  )
}

// ── ValidationModal ───────────────────────────────────────────────────────────

function ValidationModal({ type, validation, onClose }) {
  if (!validation) return null
  const isSkipped = !!validation.skipped
  const isValid   = validation.valid === true
  const details   = validation.details   // for alertrule Sigma parse
  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-box max-w-lg">
        <div className="modal-header">
          <div className="flex items-center gap-2">
            {isSkipped
              ? <AlertCircle size={15} className="text-amber-500" />
              : isValid
                ? <CheckCircle size={15} className="text-green-600" />
                : <AlertCircle size={15} className="text-red-500" />}
            <span className="text-sm font-semibold">Validation Result</span>
          </div>
          <button className="icon-btn" onClick={onClose}><X size={14} /></button>
        </div>
        <div className="p-5 space-y-4">
          {isSkipped ? (
            <div className="rounded-lg bg-amber-50 border border-amber-200 p-3 space-y-1.5">
              <p className="text-xs font-semibold text-amber-700">Validation skipped</p>
              <p className="text-xs text-amber-600">{validation.warning}</p>
            </div>
          ) : isValid ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <CheckCircle size={14} className="text-green-600" />
                <span className="text-sm font-semibold text-green-700">Valid</span>
              </div>
              {details && (
                <div className="rounded-lg bg-white border border-gray-200 p-3 space-y-2 text-xs">
                  {details.name && (
                    <div><span className="text-gray-500 font-medium">Name: </span><span className="text-gray-800">{details.name}</span></div>
                  )}
                  {details.description && (
                    <div><span className="text-gray-500 font-medium">Description: </span><span className="text-gray-700">{details.description}</span></div>
                  )}
                  {details.category && (
                    <div><span className="text-gray-500 font-medium">Category: </span><span className="text-gray-700">{details.category}</span></div>
                  )}
                  {details.artifact_type && (
                    <div><span className="text-gray-500 font-medium">Artifact type: </span><span className="text-gray-700">{details.artifact_type}</span></div>
                  )}
                  {details.query && (
                    <div>
                      <p className="text-gray-500 font-medium mb-1">ES Query:</p>
                      <code className="block bg-white border border-gray-200 rounded px-2 py-1.5 text-indigo-700 text-[11px] font-mono break-all whitespace-pre-wrap">{details.query}</code>
                    </div>
                  )}
                  {details.sigma_level && (
                    <div><span className="text-gray-500 font-medium">Level: </span>
                      <span className={`badge text-[10px] ml-1 ${
                        details.sigma_level === 'critical' ? 'bg-red-100 text-red-700 border-red-200' :
                        details.sigma_level === 'high'     ? 'bg-orange-100 text-orange-700 border-orange-200' :
                        details.sigma_level === 'medium'   ? 'bg-yellow-100 text-yellow-700 border-yellow-200' :
                        'bg-gray-100 text-gray-600 border-gray-200'
                      }`}>{details.sigma_level}</span>
                    </div>
                  )}
                  {(details.sigma_tags || []).length > 0 && (
                    <div>
                      <p className="text-gray-500 font-medium mb-1">Tags:</p>
                      <div className="flex flex-wrap gap-1">
                        {details.sigma_tags.map((t, i) => (
                          <span key={i} className="badge bg-blue-50 text-blue-600 border-blue-200 text-[10px]">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {details.customInfo && (
                    <div>
                      <p className="text-gray-500 font-medium mb-1">Query (custom rule):</p>
                      <code className="block bg-white border border-gray-200 rounded px-2 py-1.5 text-indigo-700 text-[11px] font-mono break-all">{details.customInfo}</code>
                    </div>
                  )}
                </div>
              )}
              {!details && validation.info && (
                <p className="text-xs text-gray-600 bg-gray-50 border border-gray-200 rounded px-3 py-2">{validation.info}</p>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <AlertCircle size={14} className="text-red-500" />
                <span className="text-sm font-semibold text-red-700">Invalid</span>
              </div>
              <pre className="text-[11px] text-red-700 font-mono whitespace-pre-wrap break-all bg-red-50 border border-red-200 rounded-lg px-3 py-2.5 leading-relaxed">
                {validation.error}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Studio() {
  const location = useLocation()

  // Sidebar panel: 'ingesters' | 'modules' | 'alertrule'
  const [sidebarTab, setSidebarTab]     = useState('ingesters')

  // Ingester / module file lists
  const [ingesterFiles, setIngFiles]    = useState([])
  const [moduleFiles,   setModFiles]    = useState([])
  const [refModFiles,   setRefModFiles] = useState([])
  const [showRef,       setShowRef]     = useState(false)

  // Rule lists (alert)
  const [alertRuleList,  setAlertRuleList] = useState([])

  // Alert rule drawer (create/edit via RuleDrawer)
  const [studioRuleDrawer, setStudioRuleDrawer] = useState(null) // null=closed, false=create, obj=edit

  // Alert rule sidebar filters
  const [arSearch,      setArSearch]      = useState('')
  const [arProvenance,  setArProvenance]  = useState('all')
  const [arCategory,    setArCategory]    = useState('all')

  // YARA rule list + modal state
  const [yaraRules,     setYaraRules]     = useState([])
  const [yaraDrawerRule, setYaraDrawerRule] = useState(null) // null=closed, false=create, obj=edit
  const [yaraSearch,    setYaraSearch]    = useState('')

  // Multi-tab state — each tab:
  //   type, name (unique key), label (display), ruleId (for alertrule),
  //   builtin, readOnly, code, originalCode, loading, saving, validating,
  //   validation, saveMsg, copied
  const [openTabs,      setOpenTabs]     = useState([])
  const [activeTabKey,  setActiveTabKey] = useState(null)

  // Modal visibility
  const [showNew,          setShowNew]          = useState(false)
  const [showDelete,       setShowDelete]       = useState(false)
  const [showValidateModal, setShowValidateModal] = useState(false)

  // Sidebar search filter (resets on tab change)
  const [filterText, setFilterText] = useState('')
  useEffect(() => { setFilterText(''); setYaraSearch(''); setArSearch('') }, [sidebarTab])

  // Ingester priority inline-edit state
  const [editingPriority, setEditingPriority] = useState(null)  // { name, value: string }

  // Case list for module run pickers
  const [caseList, setCaseList] = useState([])
  useEffect(() => {
    api.cases.list().then(r => setCaseList(r.cases || [])).catch(() => {})
  }, [])

  // Module run-from-Studio
  const [modRun, setModRun] = useState({
    show: false, caseId: '', sources: [], selectedJobs: [], running: false, runId: null,
  })
  useEffect(() => {
    if (!modRun.show || !modRun.caseId) return
    api.modules.listSources(modRun.caseId)
      .then(r => setModRun(p => ({ ...p, sources: r.sources || [], selectedJobs: [] })))
      .catch(() => {})
  }, [modRun.show, modRun.caseId])

  // Live log panel (SSE)
  const [logPanel, setLogPanel] = useState({ show: false, lines: [], done: false, runId: null })
  const esRef = useRef(null)

  function openLogStream(runId) {
    if (esRef.current) esRef.current.close()
    setLogPanel({ show: true, lines: [], done: false, runId })
    const url = api.modules.logStreamUrl(runId)
    const token = getToken()
    // Pass token via query param (EventSource doesn't support custom headers)
    const es = new EventSource(`${url}?_token=${encodeURIComponent(token || '')}`)
    esRef.current = es
    es.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.done) {
          setLogPanel(p => ({ ...p, done: true }))
          es.close()
          return
        }
        if (msg.text) {
          setLogPanel(p => ({ ...p, lines: [...p.lines, msg.text] }))
        }
      } catch (_) {}
    }
    es.onerror = () => {
      setLogPanel(p => ({ ...p, done: true }))
      es.close()
    }
  }

  // Derived
  const activeTab = openTabs.find(t => fileId(t.type, t.name) === activeTabKey) || null
  const isDirty   = activeTab ? activeTab.code !== activeTab.originalCode : false

  // ── Tab mutation helper ────────────────────────────────────────────────────

  function updateTab(type, name, patch) {
    setOpenTabs(tabs => tabs.map(t =>
      t.type === type && t.name === name ? { ...t, ...patch } : t
    ))
  }

  // ── Load all lists ─────────────────────────────────────────────────────────

  const loadLists = useCallback(async () => {
    try {
      const [ing, mod, ingBuiltin, modBuiltin, procFiles, alertLib, yaraLib] = await Promise.all([
        api.editor.listIngesters(),
        api.editor.listModules(),
        api.editor.listBuiltinIngesters().catch(() => ({ files: [] })),
        api.editor.listBuiltinModules().catch(() => ({ files: [] })),
        api.editor.listProcessorFiles().catch(() => ({ files: [] })),
        api.alertRules.listLibrary().catch(() => ({ rules: [] })),
        api.yaraRules.list().catch(() => ({ rules: [] })),
      ])
      setIngFiles([...(ingBuiltin.files || []), ...(ing.files || [])])
      setModFiles([
        ...(modBuiltin.files || []),
        ...(procFiles.files || []),
        ...(mod.files || []),
      ])
      setRefModFiles(modBuiltin.files || [])
      setAlertRuleList([...(alertLib.rules || [])].sort((a, b) => a.name.localeCompare(b.name)))
      setYaraRules([...(yaraLib.rules || [])].sort((a, b) => a.name.localeCompare(b.name)))
    } catch (_) {}
  }, [])

  useEffect(() => { loadLists() }, [loadLists])

  // ── Auto-open file when navigated from Modules / Ingesters pages ──────────

  const didAutoOpen = useRef(false)
  useEffect(() => {
    if (didAutoOpen.current) return
    const state = location.state
    if (!state?.type) return
    const { type, name } = state

    const fileList = type === 'module' ? moduleFiles : ingesterFiles
    if (fileList.length === 0) return
    didAutoOpen.current = true
    setSidebarTab(type === 'module' ? 'modules' : 'ingesters')
    if (name) {
      // `name` may be an exact filename (preferred — passed as source_file) or
      // a plugin display name. Try exact, then the known suffix conventions,
      // then a stem match so built-in *_plugin.py files resolve too.
      const suffix = type === 'module' ? '_module.py' : '_ingester.py'
      const lc = name.toLowerCase()
      const candidateName =
        fileList.includes(name) ? name
        : fileList.includes(name + suffix) ? name + suffix
        : fileList.includes(name + '_plugin.py') ? name + '_plugin.py'
        : fileList.includes(name + '.py') ? name + '.py'
        : fileList.find(f => f.toLowerCase().replace(/\.py$/, '').replace(/_(plugin|ingester|module)$/, '') === lc)
        || null
      if (candidateName) {
        setTimeout(() => openFile(type, candidateName), 50)
      }
    }
  }, [location.state, ingesterFiles, moduleFiles]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Open a file or rule (or switch to existing tab) ───────────────────────

  async function openFile(type, name, builtin = false) {
    setStudioRuleDrawer(null)
    setYaraDrawerRule(null)
    const key = fileId(type, name)

    if (openTabs.some(t => fileId(t.type, t.name) === key)) {
      setActiveTabKey(key)
      return
    }

    const readOnly = false

    const newTab = {
      type, name, label: name, ruleId: type === 'alertrule' ? name : null,
      builtin, readOnly,
      code: '', originalCode: '',
      loading: true, saving: false, validating: false,
      validation: null, saveMsg: null, copied: false,
    }
    setOpenTabs(tabs => [...tabs, newTab])
    setActiveTabKey(key)

    try {
      let code = ''
      let label = name

      if (type === 'alertrule') {
        const rule = await api.alertRules.getLibraryRule(name)
        code  = rule.sigma_yaml || `# Custom alert rule\nname: ${rule.name || ''}\ndescription: ${rule.description || ''}\ncategory: ${rule.category || ''}\nartifact_type: ${rule.artifact_type || ''}\nquery: ${rule.query || ''}\nthreshold: ${rule.threshold ?? 1}\n`
        label = rule.name || name
      } else if (builtin) {
        const isProcessor     = type === 'module' && name.includes('/')
        const isPlatformModule = type === 'module' && name.endsWith('_module.py') && !name.includes('/')
        const res = type === 'ingester'
          ? await api.editor.getBuiltinIngester(name)
          : isPlatformModule
            ? await api.editor.getModule(name)
            : isProcessor
              ? await api.editor.getProcessorFile(name)
              : await api.editor.getBuiltinModule(name)
        code = res.content
      } else {
        const res = type === 'ingester'
          ? await api.editor.getIngester(name)
          : await api.editor.getModule(name)
        code = res.content
      }

      updateTab(type, name, { code, originalCode: code, label, loading: false })
    } catch (err) {
      setOpenTabs(tabs => tabs.filter(t => fileId(t.type, t.name) !== key))
      setActiveTabKey(prev => prev === key ? null : prev)
      alert('Failed to load: ' + err.message)
    }
  }

  // ── Close a tab ───────────────────────────────────────────────────────────

  function closeTab(type, name) {
    const tab = openTabs.find(t => t.type === type && t.name === name)
    if (!tab) return
    if (tab.code !== tab.originalCode) {
      if (!confirm(`Discard unsaved changes to ${tab.label || name}?`)) return
    }
    const key       = fileId(type, name)
    const idx       = openTabs.findIndex(t => fileId(t.type, t.name) === key)
    const remaining = openTabs.filter(t => fileId(t.type, t.name) !== key)
    setOpenTabs(remaining)
    if (activeTabKey === key) {
      const nextTab = remaining[idx] ?? remaining[idx - 1] ?? null
      setActiveTabKey(nextTab ? fileId(nextTab.type, nextTab.name) : null)
    }
  }

  // ── Create new file / rule ─────────────────────────────────────────────────

  async function handleCreate(name, subtype, buildFn) {
    const type = sidebarTypeForCreate()

    if (type === 'ingester' || type === 'module') {
      // ── Code file: save immediately with template ──────────────────────────
      const stem     = name.replace(/_ingester\.py$/, '').replace(/_module\.py$/, '')
      const defaultBuild = type === 'ingester' ? INGESTER_TEMPLATE : MODULE_TEMPLATE
      const template = (buildFn || defaultBuild)(stem)
      const key      = fileId(type, name)

      const newTab = {
        type, name, label: name, ruleId: null,
        builtin: false, readOnly: false,
        code: template, originalCode: template,
        loading: false, saving: true, validating: false,
        validation: null, saveMsg: null, copied: false,
      }
      setOpenTabs(tabs => {
        const exists = tabs.some(t => fileId(t.type, t.name) === key)
        return exists ? tabs.map(t => fileId(t.type, t.name) === key ? newTab : t) : [...tabs, newTab]
      })
      setActiveTabKey(key)

      try {
        if (type === 'ingester') await api.editor.saveIngester(name, { content: template })
        else                     await api.editor.saveModule(name, { content: template })
        await loadLists()
        updateTab(type, name, { saving: false, saveMsg: { ok: true, text: 'File created' } })
        setTimeout(() => updateTab(type, name, { saveMsg: null }), 3000)
      } catch (err) {
        updateTab(type, name, { saving: false })
        alert('Create failed: ' + err.message)
      }
    }
  }

  function sidebarTypeForCreate() {
    if (sidebarTab === 'ingesters')  return 'ingester'
    if (sidebarTab === 'modules')    return 'module'
    return 'ingester'
  }

  // ── Save active tab ────────────────────────────────────────────────────────

  async function handleSave() {
    if (!activeTab) return
    const { type, name, label, code, ruleId, builtin } = activeTab

    if (type === 'ingester' || type === 'module') {
      updateTab(type, name, { saving: true, validation: null, saveMsg: null })
      try {
        if (builtin) {
          const isProcessor = type === 'module' && name.endsWith('.py')
          if (type === 'ingester')   await api.editor.saveBuiltinIngester(name, { content: code })
          else if (isProcessor)      await api.editor.saveProcessorFile(name, { content: code })
          else                       await api.editor.saveBuiltinModule(name, { content: code })
        } else {
          if (type === 'ingester') await api.editor.saveIngester(name, { content: code })
          else                     await api.editor.saveModule(name, { content: code })
        }
        updateTab(type, name, { originalCode: code, saving: false, saveMsg: { ok: true, text: 'Saved' } })
        setTimeout(() => updateTab(type, name, { saveMsg: null }), 3000)
      } catch (err) {
        updateTab(type, name, { saving: false, saveMsg: { ok: false, text: err.message } })
      }

    }
  }

  // ── Validate active tab ────────────────────────────────────────────────────

  async function handleValidate() {
    if (!activeTab) return
    const { type, name, code } = activeTab
    setShowValidateModal(false)
    updateTab(type, name, { validating: true, validation: null })
    try {
      let res
      if (type === 'ingester' || type === 'module') {
        res = await api.editor.validate(code)
      }
      updateTab(type, name, { validating: false, validation: res })
    } catch (_) {
      updateTab(type, name, { validating: false, validation: { valid: false, error: 'Validation request failed' } })
    }
  }

  // ── Delete active tab's file or rule ──────────────────────────────────────

  async function handleDelete() {
    if (!activeTab) return
    setShowDelete(false)
    const { type, name, ruleId, builtin } = activeTab
    const key = fileId(type, name)
    const idx = openTabs.findIndex(t => fileId(t.type, t.name) === key)
    try {
      if (type === 'alertrule') {
        if (ruleId) await api.alertRules.deleteLibraryRule(ruleId)
      } else if (builtin) {
        if (type === 'ingester') await api.editor.deleteBuiltinIngester(name)
        else                     await api.editor.deleteBuiltinModule(name)
      } else {
        if (type === 'ingester') await api.editor.deleteIngester(name)
        else                     await api.editor.deleteModule(name)
      }
      const remaining = openTabs.filter(t => fileId(t.type, t.name) !== key)
      setOpenTabs(remaining)
      const nextTab = remaining[idx] ?? remaining[idx - 1] ?? null
      setActiveTabKey(nextTab ? fileId(nextTab.type, nextTab.name) : null)
      await loadLists()
    } catch (err) {
      alert('Delete failed: ' + err.message)
    }
  }

  // ── Copy active tab ────────────────────────────────────────────────────────

  function handleCopy() {
    if (!activeTab) return
    const { type, name, code } = activeTab
    navigator.clipboard.writeText(code)
    updateTab(type, name, { copied: true })
    setTimeout(() => updateTab(type, name, { copied: false }), 2000)
  }

  // ── Run module from Studio ──────────────────────────────────────────────────

  async function runModuleFromStudio() {
    if (!activeTab || !modRun.caseId || !modRun.selectedJobs.length) return
    const moduleId = activeTab.name.replace(/_module\.py$/, '')
    setModRun(p => ({ ...p, running: true, runId: null }))
    try {
      const r = await api.modules.createRun(modRun.caseId, {
        module_id:    moduleId,
        source_files: modRun.sources
          .filter(s => modRun.selectedJobs.includes(s.job_id))
          .map(s => ({ job_id: s.job_id, filename: s.original_filename, minio_key: s.minio_object_key })),
      })
      setModRun(p => ({ ...p, running: false, runId: r.run_id, show: false }))
      openLogStream(r.run_id)
    } catch (err) {
      setModRun(p => ({ ...p, running: false }))
      alert('Dispatch failed: ' + err.message)
    }
  }

  // ── Priority editing ────────────────────────────────────────────────────────

  async function savePriority(name, valueStr) {
    const value = parseInt(valueStr, 10)
    if (isNaN(value) || value < 0) { setEditingPriority(null); return }
    try {
      await api.editor.patchIngesterPriority(name, value)
      setEditingPriority(null)
      await loadLists()
    } catch (err) {
      alert('Priority update failed: ' + err.message)
    }
  }

  // ── Sidebar helpers ────────────────────────────────────────────────────────

  const sidebarFiles    = sidebarTab === 'ingesters' ? ingesterFiles : moduleFiles
  const sidebarFileType = sidebarTab === 'ingesters' ? 'ingester' : 'module'
  const existingNames   = sidebarFiles.map(f => f.name)

  // `tool` = the suite tool that runs this artifact (shown as ownership info,
  // tabs keep their functional names per the contract).
  const SIDEBAR_TABS = [
    { id: 'ingesters', icon: <Puzzle size={12} />, label: 'Ingest.', tool: 'Babel' },
    { id: 'modules',   icon: <Cpu    size={12} />, label: 'Modules', tool: 'Anvil' },
    { id: 'alertrule', icon: <Bell   size={12} />, label: 'Rules',   tool: 'Sigil' },
    { id: 'yara',      icon: <Shield size={12} />, label: 'YARA',    tool: 'Sigil' },
  ]
  const activeTool = (SIDEBAR_TABS.find(t => t.id === sidebarTab) || {}).tool

  // ── New button label ───────────────────────────────────────────────────────

  const newBtnLabel = {
    ingesters: 'New Ingester',
    modules:   'New Module',
    alertrule: 'New Rule',
    yara:      'New YARA Rule',
  }[sidebarTab] || 'New'

  const newBtnType = {
    ingesters: 'ingester', modules: 'module', alertrule: 'alertrule',
  }[sidebarTab]

  // ── Render sidebar file list (for ingesters/modules) ──────────────────────

  function renderCodeFileSidebar(files, type) {
    const filtered = filterText
      ? files.filter(f => f.name.toLowerCase().includes(filterText.toLowerCase()))
      : files
    if (files.length === 0) {
      return (
        <div className="px-3 py-4 text-center">
          <FileCode2 size={20} className="text-gray-500 mx-auto mb-2" />
          <p className="text-[11px] text-gray-500">No files yet</p>
        </div>
      )
    }
    if (filtered.length === 0) {
      return <p className="px-3 py-2 text-[11px] text-gray-500 italic">No matches</p>
    }
    const isYaml = f => /\.(yaml|yml)$/i.test(f.name)
    const editable = type === 'module' ? filtered.filter(f => !isYaml(f)) : filtered
    const builtins = editable.filter(f => f.builtin)
    const customs  = editable.filter(f => !f.builtin)
    const renderFile = f => {
      const key              = fileId(type, f.name)
      const isActive         = activeTabKey === key
      const openTab          = openTabs.find(t => fileId(t.type, t.name) === key)
      const isOpen           = Boolean(openTab)
      const isDirtyTab       = isOpen && openTab.code !== openTab.originalCode
      const isPriorityEdit   = type === 'ingester' && !f.builtin && editingPriority?.name === f.name
      const showPriorityBadge = type === 'ingester' && !f.builtin

      return (
        <div
          key={f.name}
          className={`flex items-center transition-colors ${
            isActive ? 'bg-brand-accentlight'
            : isOpen  ? 'bg-blue-50/50'
            : ''
          }`}
        >
          <button
            onClick={() => openFile(type, f.name, !!f.builtin)}
            className={`flex items-center gap-2 px-3 py-1.5 text-left flex-1 min-w-0 transition-colors ${
              isActive ? 'text-brand-accent'
              : isOpen  ? 'text-gray-700 hover:bg-blue-50'
              : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
            }`}
          >
            <FileCode2 size={13} className="flex-shrink-0 opacity-60" />
            <span className="text-[11px] font-mono truncate flex-1">{f.name}</span>
            {isDirtyTab && <span className="w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0" />}
            {isActive && !isDirtyTab && <ChevronRight size={10} className="flex-shrink-0 opacity-50" />}
          </button>

          {showPriorityBadge && (
            <div className="pr-2 flex-shrink-0">
              {isPriorityEdit ? (
                <input
                  type="number"
                  min="0"
                  value={editingPriority.value}
                  onChange={e => setEditingPriority(p => ({ ...p, value: e.target.value }))}
                  onBlur={() => savePriority(f.name, editingPriority.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter')  savePriority(f.name, editingPriority.value)
                    if (e.key === 'Escape') setEditingPriority(null)
                    e.stopPropagation()
                  }}
                  autoFocus
                  className="w-10 text-[10px] text-center border border-brand-accent rounded px-1 py-0.5 bg-white text-brand-accent"
                />
              ) : (
                <span
                  onClick={() => setEditingPriority({ name: f.name, value: String(f.priority ?? '') })}
                  title="Click to edit PLUGIN_PRIORITY"
                  className={`text-[10px] px-1.5 py-0.5 rounded border cursor-pointer hover:border-brand-accent hover:text-brand-accent transition-colors ${
                    f.priority !== undefined
                      ? 'bg-blue-50 text-blue-600 border-blue-200'
                      : 'bg-gray-100 text-gray-500 border-gray-200'
                  }`}
                >
                  P{f.priority !== undefined ? f.priority : '?'}
                </span>
              )}
            </div>
          )}
        </div>
      )
    }
    return (
      <>
        {builtins.length > 0 && (
          <>
            <p className="px-3 pt-2 pb-1 text-[10px] font-semibold text-gray-500 uppercase tracking-widest">Built-in</p>
            {builtins.map(renderFile)}
          </>
        )}
        {customs.length > 0 && (
          <>
            <p className="px-3 pt-3 pb-1 text-[10px] font-semibold text-gray-500 uppercase tracking-widest">Custom</p>
            {customs.map(renderFile)}
          </>
        )}
      </>
    )
  }

  return (
    <div className="flex h-full overflow-hidden">

      {/* ── Sidebar ─────────────────────────────────────────────────────────── */}
      <aside className="w-64 flex-shrink-0 flex flex-col border-r border-gray-200 bg-white overflow-hidden">

        {/* Panel tab switcher — 4 tabs */}
        <div className="flex border-b border-gray-200 flex-shrink-0">
          {SIDEBAR_TABS.map(({ id, icon, label, tool }) => (
            <button
              key={id}
              onClick={() => setSidebarTab(id)}
              title={tool ? `${label} — run by ${tool}` : label}
              className={`flex-1 flex flex-col items-center justify-center gap-0.5 py-2 text-[10px] font-medium transition-colors ${
                sidebarTab === id
                  ? 'text-brand-accent border-b-2 border-brand-accent bg-brand-accentlight/40'
                  : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
              }`}
            >
              {icon}
              <span>{label}</span>
            </button>
          ))}
        </div>

        {/* Owning-tool note — tabs keep functional names; this says who runs it. */}
        {activeTool && (
          <div className="px-3 pt-1.5 text-[10px] text-gray-400">
            run by <span className="font-semibold text-brand-accent">{activeTool}</span>
          </div>
        )}

        {/* New button + filter */}
        <div className="px-3 py-2 space-y-1.5 flex-shrink-0">
          <button
            onClick={() => {
              if (sidebarTab === 'alertrule') setStudioRuleDrawer(false)
              else if (sidebarTab === 'yara') setYaraDrawerRule(false)
              else setShowNew(true)
            }}
            className="w-full btn-primary text-xs justify-center py-1.5"
          >
            <Plus size={12} /> {newBtnLabel}
          </button>
          {sidebarTab === 'alertrule' ? (
            <input
              value={arSearch}
              onChange={e => setArSearch(e.target.value)}
              placeholder="Search rules…"
              className="input w-full text-xs py-1"
            />
          ) : sidebarTab === 'yara' ? (
            <input
              value={yaraSearch}
              onChange={e => setYaraSearch(e.target.value)}
              placeholder="Search YARA rules…"
              className="input w-full text-xs py-1"
            />
          ) : (
            <input
              value={filterText}
              onChange={e => setFilterText(e.target.value)}
              placeholder="Filter…"
              className="input w-full text-xs py-1"
            />
          )}
        </div>

        {/* Alert rule filters */}
        {sidebarTab === 'alertrule' && (
          <div className="px-3 pb-2 space-y-1.5 flex-shrink-0 border-b border-gray-100">
            <ProvenancePills value={arProvenance} onChange={setArProvenance} size="xs" />
            {alertRuleList.length > 0 && (
              <select value={arCategory} onChange={e => setArCategory(e.target.value)}
                className="w-full input text-[10px] py-0.5 h-6">
                <option value="all">All categories</option>
                {CATEGORY_ORDER.filter(cat =>
                  alertRuleList.some(r => (r.category || 'Other') === cat)
                ).map(cat => <option key={cat} value={cat}>{cat}</option>)}
              </select>
            )}
          </div>
        )}

        {/* File / rule list */}
        <div className="flex-1 overflow-y-auto py-1 min-h-0">
          {sidebarTab === 'ingesters' && renderCodeFileSidebar(ingesterFiles, 'ingester')}
          {sidebarTab === 'modules'   && renderCodeFileSidebar(moduleFiles,   'module')}
          {sidebarTab === 'yara' && (() => {
            const filtered = yaraRules.filter(r =>
              !yaraSearch || r.name.toLowerCase().includes(yaraSearch.toLowerCase())
            )
            if (yaraRules.length === 0) return (
              <div className="px-3 py-6 text-center">
                <Shield size={20} className="text-gray-500 mx-auto mb-2" />
                <p className="text-[11px] text-gray-500">No YARA rules yet</p>
                <button onClick={() => setYaraDrawerRule(false)} className="btn-primary text-xs mt-2 mx-auto">
                  <Plus size={11} /> Create Rule
                </button>
              </div>
            )
            if (filtered.length === 0) return (
              <p className="px-3 py-2 text-[11px] text-gray-500 italic">No matches</p>
            )
            return filtered.map(r => (
              <div
                key={r.id}
                onClick={() => setYaraDrawerRule(r)}
                className={`px-3 py-1.5 cursor-pointer transition-colors ${
                  yaraDrawerRule?.id === r.id ? 'bg-green-50 border-l-2 border-green-500' : 'hover:bg-gray-50'
                }`}
              >
                <span className="text-[11px] text-gray-700 truncate block leading-tight">{r.name}</span>
                {r.tags?.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-0.5">
                    {r.tags.slice(0, 3).map(t => (
                      <span key={t} className="text-[10px] bg-green-50 text-green-600 border border-green-100 rounded px-1">{t}</span>
                    ))}
                  </div>
                )}
              </div>
            ))
          })()}
          {sidebarTab === 'alertrule' && (() => {
            const filtered = filterAlertRules(alertRuleList, {
              search: arSearch, provenance: arProvenance, category: arCategory,
            })

            if (alertRuleList.length === 0) return (
              <div className="px-3 py-6 text-center">
                <Bell size={20} className="text-gray-500 mx-auto mb-2" />
                <p className="text-[11px] text-gray-500">No rules yet</p>
                <button onClick={() => setStudioRuleDrawer(false)} className="btn-primary text-xs mt-2 mx-auto">
                  <Plus size={11} /> Create Rule
                </button>
              </div>
            )

            if (filtered.length === 0) return (
              <p className="px-3 py-2 text-[11px] text-gray-500 italic">No matches</p>
            )

            return filtered.map(r => {
              const isSigma = r.rule_type === 'sigma' || (!r.rule_type && !!r.sigma_yaml)
              const cat = r.category || 'Other'
              const catStyle = CATEGORY_STYLES[cat] || CATEGORY_STYLES['Other']
              return (
                <div
                  key={r.id}
                  onClick={() => setStudioRuleDrawer(r)}
                  className={`px-3 py-1.5 cursor-pointer transition-colors ${
                    studioRuleDrawer?.id === r.id ? 'bg-indigo-50 border-l-2 border-indigo-500' : 'hover:bg-gray-50'
                  }`}
                >
                  <div title={r.name} className="flex items-center gap-1 mb-0.5 min-w-0">
                    <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${catStyle.dot}`} />
                    <span className="text-[11px] text-gray-700 truncate leading-tight">{r.name}</span>
                  </div>
                  <div className="flex items-center gap-1 flex-wrap">
                    {r.sigma_level && (
                      <span className={`text-[10px] border rounded px-1 ${
                        r.sigma_level === 'critical' ? 'text-red-600 bg-red-50 border-red-200' :
                        r.sigma_level === 'high'     ? 'text-orange-600 bg-orange-50 border-orange-200' :
                        r.sigma_level === 'medium'   ? 'text-yellow-600 bg-yellow-50 border-yellow-200' :
                        'text-gray-500 bg-gray-50 border-gray-200'
                      }`}>{r.sigma_level}</span>
                    )}
                  </div>
                </div>
              )
            })
          })()}
        </div>

        {/* Module Registry Reference (YAML files, read-only) */}
        {sidebarTab === 'modules' && refModFiles.length > 0 && (
          <div className="border-t border-gray-200 flex-shrink-0">
            <button
              onClick={() => setShowRef(v => !v)}
              className="w-full flex items-center gap-1.5 px-3 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-widest hover:bg-gray-50 transition-colors"
            >
              <BookOpen size={10} />
              Registry Reference
              <ChevronRight size={10} className={`ml-auto transition-transform ${showRef ? 'rotate-90' : ''}`} />
            </button>
            {showRef && (
              <div className="py-1 max-h-40 overflow-y-auto">
                {refModFiles.map(f => (
                  <button
                    key={f.name}
                    onClick={() => openFile('module', f.name, true)}
                    className="w-full flex items-center gap-2 px-3 py-1.5 text-left text-gray-500 hover:bg-gray-50 hover:text-gray-600 transition-colors"
                  >
                    <Lock size={9} className="flex-shrink-0 opacity-50" />
                    <span className="text-[10px] font-mono truncate flex-1">{f.name}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </aside>

      {/* ── Editor pane ─────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">

        {/* Tab bar */}
        {openTabs.length > 0 && (
          <div className="flex items-stretch border-b border-gray-200 bg-gray-50/80 overflow-x-auto flex-shrink-0">
            {openTabs.map(t => {
              const key      = fileId(t.type, t.name)
              const isActive = key === activeTabKey
              const tabDirty = t.code !== t.originalCode
              const badge    = TYPE_BADGE[t.type] || TYPE_BADGE.ingester

              return (
                <div
                  key={key}
                  onClick={() => setActiveTabKey(key)}
                  className={`flex items-center gap-1.5 px-3 py-2 border-r border-gray-200
                    cursor-pointer flex-shrink-0 max-w-[200px] group transition-colors
                    ${isActive
                      ? 'bg-white border-b-2 border-b-brand-accent text-gray-800'
                      : 'border-b-2 border-b-transparent text-gray-500 hover:bg-gray-100 hover:text-gray-700'
                    }`}
                >
                  <span className={`text-[10px] px-1 py-px rounded font-bold flex-shrink-0 ${badge.cls}`}>
                    {badge.letter}
                  </span>
                  <span className="text-[11px] font-mono truncate flex-1 min-w-0">
                    {t.label || t.name}
                  </span>
                  {tabDirty && (
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0 group-hover:hidden" title="Unsaved changes" />
                  )}
                  <button
                    onClick={e => { e.stopPropagation(); closeTab(t.type, t.name) }}
                    className={`rounded p-0.5 hover:bg-gray-200 flex-shrink-0 transition-opacity
                      ${isActive ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}
                    title="Close tab"
                  >
                    <X size={9} className="text-gray-500" />
                  </button>
                </div>
              )
            })}
          </div>
        )}

        {studioRuleDrawer !== null ? (
          <RuleDrawer
            key={studioRuleDrawer ? `rule-${studioRuleDrawer.id}` : 'new-rule'}
            inline
            rule={studioRuleDrawer || null}
            onClose={() => setStudioRuleDrawer(null)}
            onSaved={async () => { await loadLists(); setStudioRuleDrawer(null) }}
          />
        ) : yaraDrawerRule !== null ? (
          <YaraRuleModal
            key={yaraDrawerRule ? `yara-${yaraDrawerRule.id}` : 'new-yara'}
            inline
            rule={yaraDrawerRule || null}
            onClose={() => setYaraDrawerRule(null)}
            onSaved={async () => { await loadLists(); setYaraDrawerRule(null) }}
          />
        ) : activeTab ? (
          <>
            {/* Editor toolbar */}
            <div className="flex items-center justify-between px-4 py-2 border-b border-gray-200 bg-white flex-shrink-0 gap-3">
              <div className="flex items-center gap-2 min-w-0">
                <span className={`badge text-[10px] ${(TYPE_TOOLBAR[activeTab.type] || TYPE_TOOLBAR.ingester).cls}`}>
                  {(TYPE_TOOLBAR[activeTab.type] || TYPE_TOOLBAR.ingester).label}
                </span>
                <code className="text-xs font-mono text-gray-700 truncate">
                  {activeTab.label || activeTab.name}
                </code>
                {isDirty && <span className="w-2 h-2 rounded-full bg-amber-400 flex-shrink-0" title="Unsaved changes" />}
              </div>

              <div className="flex items-center gap-1.5 flex-shrink-0">
                {/* Module: Run button */}
                {activeTab.type === 'module' && !activeTab.builtin && (
                  <button
                    onClick={() => setModRun(p => ({ ...p, show: true }))}
                    className="btn-outline text-xs py-1 px-2 text-purple-700 border-purple-200 hover:bg-purple-50"
                  >
                    <Play size={12} /> Run
                  </button>
                )}
                {/* Log panel toggle */}
                {logPanel.runId && (
                  <button
                    onClick={() => setLogPanel(p => ({ ...p, show: !p.show }))}
                    className={`btn-outline text-xs py-1 px-2 flex items-center gap-1 ${logPanel.show ? 'bg-gray-100' : ''}`}
                  >
                    <Terminal size={12} />
                    Log
                    {!logPanel.done && <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />}
                  </button>
                )}
                {/* Validation result — click to open full modal */}
                {activeTab.validation && (
                  activeTab.validation.valid
                    ? <button
                        onClick={() => setShowValidateModal(true)}
                        className="flex items-center gap-1 text-[11px] text-green-700 bg-green-50 border border-green-200 rounded-lg px-2 py-0.5 hover:bg-green-100 transition-colors"
                      >
                        <CheckCircle size={11} />
                        {activeTab.validation.info || 'Valid'}
                      </button>
                    : <button
                        onClick={() => setShowValidateModal(true)}
                        className="flex items-center gap-1 text-[11px] text-red-600 bg-red-50 border border-red-200 rounded-lg px-2 py-0.5 max-w-xs hover:bg-red-100 transition-colors"
                        title="Click to see full error"
                      >
                        <AlertCircle size={11} />
                        <span className="truncate max-w-[180px]">{activeTab.validation.error?.split('\n')[0]}</span>
                        <span className="text-[10px] underline flex-shrink-0">details</span>
                      </button>
                )}
                {/* Warning (yara: skipped) */}
                {activeTab.validation?.warning && (
                  <button
                    onClick={() => setShowValidateModal(true)}
                    className="text-[11px] text-amber-600 bg-amber-50 border border-amber-200 rounded-lg px-2 py-0.5 hover:bg-amber-100 transition-colors"
                  >
                    {activeTab.validation.warning}
                  </button>
                )}

                {/* Save message */}
                {activeTab.saveMsg && (
                  <span className={`text-[11px] ${activeTab.saveMsg.ok ? 'text-green-700' : 'text-red-600'}`}>
                    {activeTab.saveMsg.ok
                      ? <CheckCircle size={11} className="inline mr-1" />
                      : <AlertCircle size={11} className="inline mr-1" />}
                    {activeTab.saveMsg.text}
                  </span>
                )}

                <button onClick={handleCopy} className="btn-ghost text-xs py-1 px-2">
                  {activeTab.copied
                    ? <><Check size={12} className="text-green-600" /> Copied</>
                    : <><Copy size={12} /> Copy</>}
                </button>

                {activeTab.readOnly ? (
                  <span className="badge bg-gray-100 text-gray-500 text-[10px] flex items-center gap-1">
                    <Lock size={9} /> Read-only reference
                  </span>
                ) : (
                  <>
                    <button
                      onClick={handleValidate}
                      disabled={activeTab.validating}
                      className="btn-outline text-xs py-1 px-2"
                    >
                      {activeTab.validating
                        ? <RefreshCw size={12} className="animate-spin" />
                        : <Play size={12} />}
                      {activeTab.validating ? 'Checking…' : 'Validate'}
                    </button>
                    <button
                      onClick={handleSave}
                      disabled={activeTab.saving || (!isDirty && (activeTab.type === 'ingester' || activeTab.type === 'module'))}
                      className="btn-primary text-xs py-1 px-2"
                    >
                      {activeTab.saving
                        ? <RefreshCw size={12} className="animate-spin" />
                        : <Save size={12} />}
                      {activeTab.saving ? 'Saving…' : 'Save'}
                    </button>
                    <button
                      onClick={() => setShowDelete(true)}
                      className="btn-danger text-xs py-1 px-2"
                    >
                      <Trash2 size={12} />
                    </button>
                  </>
                )}
              </div>
            </div>

            {/* Validation error hint — click to open modal */}
            {activeTab.validation && !activeTab.validation.valid && activeTab.validation.error && (
              <button
                onClick={() => setShowValidateModal(true)}
                className="w-full bg-red-50 border-b border-red-200 px-4 py-1.5 flex items-center gap-2 hover:bg-red-100 transition-colors text-left"
              >
                <AlertCircle size={12} className="text-red-500 flex-shrink-0" />
                <span className="text-[11px] text-red-700 font-mono truncate flex-1">
                  {activeTab.validation.error.split('\n')[0]}
                </span>
                <span className="text-[10px] text-red-500 underline flex-shrink-0">View full error</span>
              </button>
            )}

            {/* Code editor + bottom panels */}
            <div className="flex-1 flex flex-col overflow-hidden min-h-0">
              <div className="flex-1 overflow-hidden min-h-0">
                {activeTab.loading ? (
                  <div className="h-full bg-gray-950 flex items-center justify-center">
                    <RefreshCw size={20} className="animate-spin text-gray-500" />
                  </div>
                ) : (
                  <CodeEditor
                    key={activeTabKey}
                    value={activeTab.code}
                    onChange={v => !activeTab.readOnly && updateTab(activeTab.type, activeTab.name, { code: v })}
                    readOnly={activeTab.readOnly}
                    tab={activeTab}
                  />
                )}
              </div>

              {/* ── Log panel ─────────────────────────────────────────────── */}
              {logPanel.show && logPanel.runId && (
                <div className="border-t border-gray-700 bg-gray-950 flex-shrink-0 max-h-48 flex flex-col">
                  <div className="flex items-center gap-2 px-4 py-1.5 border-b border-gray-800 flex-shrink-0">
                    <Terminal size={12} className="text-gray-500" />
                    <span className="text-[10px] font-mono text-gray-500">
                      run:{logPanel.runId.slice(0, 8)}
                    </span>
                    {!logPanel.done && (
                      <span className="text-[10px] text-green-400 flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse inline-block" />
                        live
                      </span>
                    )}
                    {logPanel.done && <span className="text-[10px] text-gray-500">done</span>}
                    <button className="ml-auto icon-btn" onClick={() => setLogPanel(p => ({ ...p, show: false }))}>
                      <X size={10} className="text-gray-500" />
                    </button>
                  </div>
                  <div className="flex-1 overflow-y-auto px-4 py-2 space-y-0.5">
                    {logPanel.lines.map((line, i) => (
                      <p key={i} className="text-[10px] font-mono text-gray-300 leading-relaxed">{line}</p>
                    ))}
                    {!logPanel.done && (
                      <p className="text-[10px] font-mono text-gray-500 animate-pulse">…</p>
                    )}
                  </div>
                </div>
              )}
            </div>
          </>
        ) : (
          /* Empty state */
          <div className="flex-1 flex flex-col items-center justify-center bg-white text-center p-8">
            <div className="w-16 h-16 rounded-2xl bg-gray-100 flex items-center justify-center mb-4">
              <Code2 size={28} className="text-gray-500" />
            </div>
            <p className="text-gray-500 text-sm font-medium mb-1">Select a file or rule to edit</p>
            <p className="text-gray-500 text-xs mb-6 max-w-xs">
              Choose an ingester, module, YARA rule, or alert rule from the sidebar, or create a new one.
            </p>
            <div className="flex gap-2">
              <a href="/docs" className="btn-outline text-xs">
                <BookOpen size={13} /> Read the docs
              </a>
            </div>
          </div>
        )}
      </div>

      {/* ── Modals ──────────────────────────────────────────────────────────── */}
      {showNew && (
        <NewFileModal
          type={newBtnType}
          existing={existingNames}
          onClose={() => setShowNew(false)}
          onCreate={handleCreate}
        />
      )}
      {showDelete && activeTab && (
        <DeleteConfirmModal
          file={activeTab.label || activeTab.name}
          onClose={() => setShowDelete(false)}
          onConfirm={handleDelete}
        />
      )}
      {showValidateModal && activeTab?.validation && (
        <ValidationModal
          type={activeTab.type}
          validation={activeTab.validation}
          onClose={() => setShowValidateModal(false)}
        />
      )}

      {/* ── Module Run modal ──────────────────────────────────────────────── */}
      {modRun.show && activeTab?.type === 'module' && (
        <div className="modal-overlay" onClick={e => e.target === e.currentTarget && setModRun(p => ({ ...p, show: false }))}>
          <div className="modal-box max-w-lg">
            <div className="modal-header">
              <div className="flex items-center gap-2">
                <Play size={14} className="text-purple-500" />
                <span className="text-sm font-semibold">Run module: {activeTab.label || activeTab.name}</span>
              </div>
              <button className="icon-btn" onClick={() => setModRun(p => ({ ...p, show: false }))}><X size={14} /></button>
            </div>
            <div className="p-5 space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1.5">Case</label>
                <select
                  className="input w-full"
                  value={modRun.caseId}
                  onChange={e => setModRun(p => ({ ...p, caseId: e.target.value, sources: [], selectedJobs: [] }))}
                >
                  <option value="">Select a case…</option>
                  {caseList.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </div>

              {modRun.sources.length > 0 && (
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1.5">
                    Source files <span className="text-gray-500">({modRun.selectedJobs.length} selected)</span>
                  </label>
                  <div className="border border-gray-200 rounded-lg max-h-48 overflow-y-auto">
                    {modRun.sources.map(s => (
                      <label
                        key={s.job_id}
                        className="flex items-center gap-2.5 px-3 py-2 hover:bg-gray-50 cursor-pointer border-b border-gray-100 last:border-0"
                      >
                        <input
                          type="checkbox"
                          checked={modRun.selectedJobs.includes(s.job_id)}
                          onChange={e => setModRun(p => ({
                            ...p,
                            selectedJobs: e.target.checked
                              ? [...p.selectedJobs, s.job_id]
                              : p.selectedJobs.filter(id => id !== s.job_id),
                          }))}
                        />
                        <span className="text-xs font-mono text-gray-700 truncate flex-1">{s.original_filename}</span>
                        {s.plugin_used && (
                          <span className="text-[10px] text-gray-500">{s.plugin_used}</span>
                        )}
                      </label>
                    ))}
                  </div>
                </div>
              )}

              {modRun.caseId && modRun.sources.length === 0 && (
                <p className="text-xs text-gray-500 italic">Loading sources…</p>
              )}

              <div className="flex justify-end gap-2">
                <button className="btn-ghost text-sm" onClick={() => setModRun(p => ({ ...p, show: false }))}>Cancel</button>
                <button
                  className="btn-primary text-sm"
                  disabled={modRun.running || !modRun.caseId || !modRun.selectedJobs.length}
                  onClick={runModuleFromStudio}
                >
                  {modRun.running ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />}
                  {modRun.running ? 'Dispatching…' : 'Run'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
