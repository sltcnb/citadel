import { useEffect, useState, useCallback, useRef } from 'react'
import DOMPurify from 'dompurify'
import {
  Save,
  Printer,
  Sparkles,
  Bold,
  Italic,
  Underline,
  Strikethrough,
  List,
  ListOrdered,
  Quote,
  Minus,
  Heading1,
  Heading2,
  Highlighter,
  Link,
  RemoveFormatting,
} from 'lucide-react'
import { api } from '../api/client'
import { relativeTime } from '../utils/format'
import { useCollab } from '../hooks/useCollab'
import { currentUser } from '../utils/caseConstants'

// ── WYSIWYG toolbar ───────────────────────────────────────────────────────────

function ToolbarBtn({ title, onClick, active, children }) {
  return (
    <button
      type="button"
      onMouseDown={e => { e.preventDefault(); onClick() }}
      title={title}
      className={`p-1 rounded transition-colors ${
        active ? 'bg-gray-200 text-gray-900' : 'text-gray-500 hover:bg-gray-100 hover:text-gray-800'
      }`}
    >
      {children}
    </button>
  )
}

function ToolbarSep() {
  return <div className="w-px h-4 bg-gray-200 mx-0.5 self-center" />
}

function EditorToolbar({ editorRef }) {
  const cmd = (name, value) => {
    editorRef.current?.focus()
    document.execCommand(name, false, value)
  }

  return (
    <div className="flex items-center gap-0.5 px-2 py-1.5 border-b border-gray-200 bg-gray-50 flex-wrap">
      <ToolbarBtn title="Bold (Ctrl+B)"      onClick={() => cmd('bold')}>          <Bold          size={13} /></ToolbarBtn>
      <ToolbarBtn title="Italic (Ctrl+I)"    onClick={() => cmd('italic')}>        <Italic        size={13} /></ToolbarBtn>
      <ToolbarBtn title="Underline (Ctrl+U)" onClick={() => cmd('underline')}>     <Underline     size={13} /></ToolbarBtn>
      <ToolbarBtn title="Strikethrough"      onClick={() => cmd('strikeThrough')}> <Strikethrough size={13} /></ToolbarBtn>
      <ToolbarSep />
      <ToolbarBtn title="Heading 1" onClick={() => cmd('formatBlock', '<h1>')}><Heading1 size={13} /></ToolbarBtn>
      <ToolbarBtn title="Heading 2" onClick={() => cmd('formatBlock', '<h2>')}><Heading2 size={13} /></ToolbarBtn>
      <ToolbarSep />
      <ToolbarBtn title="Bullet list"   onClick={() => cmd('insertUnorderedList')}><List        size={13} /></ToolbarBtn>
      <ToolbarBtn title="Ordered list"  onClick={() => cmd('insertOrderedList')}>  <ListOrdered size={13} /></ToolbarBtn>
      <ToolbarBtn title="Blockquote"    onClick={() => cmd('formatBlock', '<blockquote>')}><Quote size={13} /></ToolbarBtn>
      <ToolbarSep />
      <ToolbarBtn title="Highlight" onClick={() => cmd('backColor', '#fef08a')}><Highlighter size={13} /></ToolbarBtn>
      <ToolbarBtn title="Horizontal rule" onClick={() => cmd('insertHorizontalRule')}><Minus size={13} /></ToolbarBtn>
      <ToolbarBtn title="Insert link" onClick={() => {
        const url = prompt('URL:')
        if (url) cmd('createLink', url)
      }}><Link size={13} /></ToolbarBtn>
      <ToolbarSep />
      <ToolbarBtn title="Remove formatting" onClick={() => cmd('removeFormat')}><RemoveFormatting size={13} /></ToolbarBtn>
    </div>
  )
}

// ── Tab: Notes ────────────────────────────────────────────────────────────────

function NotesTab({ caseId }) {
  const editorRef = useRef(null)
  const [savedBody, setSavedBody]     = useState('')
  const [currentBody, setCurrentBody] = useState('')
  const [updatedAt, setUpdatedAt]     = useState(null)
  const [saving, setSaving]           = useState(false)
  const [error, setError]             = useState(null)
  const [staleNotice, setStaleNotice] = useState(null) // {user} — someone else saved while we had unsaved edits
  const [, setTick] = useState(0)

  // Collaborative notes: reuse the case's existing SSE collab channel (also used
  // for flag/pin/presence) rather than building a bespoke realtime layer. Other
  // clients' saves show up as 'note' events — reload if we have no unsaved
  // local edits, otherwise surface a non-destructive "stale" banner.
  const me = currentUser()
  const { events, publish } = useCollab(caseId, me)
  const lastAppliedTsRef = useRef(0)

  const reload = useCallback(() => {
    api.notes.get(caseId).then(d => {
      const body = d.body || ''
      setSavedBody(body)
      setCurrentBody(body)
      setUpdatedAt(d.updated_at)
      setError(null)
      setStaleNotice(null)
      if (editorRef.current) editorRef.current.innerHTML = DOMPurify.sanitize(body)
    }).catch(err => setError(err.message || 'Failed to load notes'))
  }, [caseId])

  useEffect(() => { reload() }, [reload])

  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 30_000)
    return () => clearInterval(id)
  }, [])

  // React to other analysts' saves broadcast over collab.
  useEffect(() => {
    const noteEvents = events.filter(e => e.type === 'note' && e.ts > lastAppliedTsRef.current)
    if (!noteEvents.length) return
    const latest = noteEvents[noteEvents.length - 1]
    lastAppliedTsRef.current = latest.ts
    if (latest.user === me?.username) return  // our own save echoing back
    const dirty = editorRef.current && editorRef.current.innerHTML !== savedBody
    if (dirty) {
      setStaleNotice({ user: latest.user })
    } else {
      reload()
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events])

  const save = useCallback(async () => {
    if (saving || !editorRef.current) return
    setSaving(true)
    const body = editorRef.current.innerHTML
    try {
      const res = await api.notes.save(caseId, body)
      setSavedBody(body)
      setCurrentBody(body)
      setUpdatedAt(res.updated_at)
      setError(null)
      setStaleNotice(null)
      publish('note', { updated_at: res.updated_at })
    } catch (err) {
      setError(err.message || 'Failed to save notes')
    } finally {
      setSaving(false)
    }
  }, [caseId, saving, publish])

  useEffect(() => {
    const handler = e => {
      if ((e.metaKey || e.ctrlKey) && e.key === 's') { e.preventDefault(); save() }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [save])

  const handlePaste = useCallback(e => {
    const items = Array.from(e.clipboardData?.items || [])
    const imageItem = items.find(item => item.type.startsWith('image/'))
    if (!imageItem) return
    e.preventDefault()
    const file = imageItem.getAsFile()
    if (!file) return
    const reader = new FileReader()
    reader.onload = evt => {
      const img = document.createElement('img')
      img.src = evt.target.result
      img.style.cssText = 'max-width:100%;border-radius:4px;margin:4px 0;display:block;'
      const sel = window.getSelection()
      if (sel?.rangeCount) {
        const range = sel.getRangeAt(0)
        range.deleteContents()
        range.insertNode(document.createElement('br'))
        range.insertNode(img)
        range.collapse(false)
        sel.removeAllRanges()
        sel.addRange(range)
      } else {
        editorRef.current.appendChild(img)
      }
      setCurrentBody(editorRef.current.innerHTML)
    }
    reader.readAsDataURL(file)
  }, [])

  const handleExportPDF = useCallback(() => {
    const content = editorRef.current?.innerHTML || ''
    const win = window.open('', '_blank')
    if (!win) return
    const esc = s => String(s).replace(/[<>&]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]))
    win.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Notes — Case ${esc(caseId)}</title>
<style>body{font-family:monospace;font-size:13px;padding:32px;line-height:1.7;color:#111;white-space:pre-wrap;word-break:break-word;}img{max-width:100%;display:block;margin:8px 0;}@media print{body{padding:0;}}</style>
</head><body>${content}</body></html>`)
    win.document.close()
    win.focus()
    setTimeout(() => { win.print(); win.close() }, 250)
  }, [caseId])

  const dirty = currentBody !== savedBody

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <EditorToolbar editorRef={editorRef} />

      {/* Save bar */}
      <div className="flex items-center justify-between px-4 py-1.5 border-b border-gray-100 bg-white flex-shrink-0">
        <div className="flex items-center gap-1.5">
          {error && <span className="text-xs text-red-600">{error}</span>}
          {!error && updatedAt && !dirty && <span className="text-xs text-gray-500">saved {relativeTime(updatedAt)}</span>}
          {!error && dirty && <span className="text-xs text-amber-500">unsaved changes</span>}
        </div>
        <div className="flex items-center gap-2">
          {staleNotice && (
            <span className="text-xs text-amber-600 flex items-center gap-1">
              {staleNotice.user || 'Another analyst'} saved newer notes —
              <button onClick={reload} className="underline hover:text-amber-700">reload</button>
            </span>
          )}
          <button onClick={handleExportPDF} className="btn-ghost text-xs flex items-center gap-1.5">
            <Printer size={11} /> Export
          </button>
          <button onClick={save} disabled={saving || !dirty} className="btn-primary text-xs flex items-center gap-1.5">
            <Save size={11} /> {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>

      {/* Editor area */}
      <div
        ref={editorRef}
        contentEditable
        suppressContentEditableWarning
        onInput={() => setCurrentBody(editorRef.current?.innerHTML || '')}
        onPaste={handlePaste}
        spellCheck={false}
        className="flex-1 overflow-auto outline-none cursor-text notes-editor"
        style={{ padding: '20px 24px', minHeight: '320px' }}
      />
      <p className="text-[10px] text-gray-500 px-4 py-1.5 border-t border-gray-100 flex-shrink-0">
        Paste screenshots directly · ⌘S / Ctrl+S to save · Use toolbar or keyboard shortcuts (Ctrl+B, Ctrl+I…)
      </p>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// CaseNotes — notes-only drawer.
//
// History: this used to be a multi-tab panel hosting Notes / AI Analysis /
// Modules / Final Report. Those flows moved out:
//   - AI Analysis  → CaseAiPanel (Sparkles button in the case header)
//   - Modules picker + Final Report → ReportPanel (Report button)
// CaseNotes is now a thin wrapper around NotesTab so the file rename + import
// chain stays unchanged.
// ─────────────────────────────────────────────────────────────────────────────
export default function CaseNotes({ caseId }) {
  return (
    <div className="flex flex-col h-full min-h-0">
      <NotesTab caseId={caseId} />
    </div>
  )
}
