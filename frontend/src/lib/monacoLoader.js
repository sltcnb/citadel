// Bundles Monaco locally instead of fetching it from a CDN at runtime.
//
// @monaco-editor/react does not bundle the editor: by default @monaco-editor/
// loader pulls it from cdn.jsdelivr.net in the browser — which leaves the
// Studio/RuleDrawer/YaraRuleModal editors blank in air-gapped deployments
// (typical for DFIR labs) and adds a supply-chain dependency we don't need,
// since monaco-editor is already a locked dependency in package.json.
//
// We import the ESM build ourselves, register an editor worker through Vite's
// `?worker` import (emitted as a local asset chunk), and hand the instance to
// @monaco-editor/react via loader.config({ monaco }), which skips the CDN
// fetch entirely. Version drift is no longer possible: the browser runs
// exactly what package-lock.json resolved.
//
// Only basic syntax highlighting is needed (yaml/python for Studio and
// RuleDrawer, plaintext otherwise, plus the custom YARA Monarch grammar in
// YaraRuleModal) — no rich language workers (json/css/html/ts), so a single
// editor worker covers everything.
//
// Import this module for side effects before mounting any <Editor>; config()
// must run before the loader's first init(). It is idempotent in practice
// because every Editor call site imports this same module instance.
// monaco-editor 0.56's exports map rewrites "./*" → "./esm/vs/*.js", so these
// specifiers intentionally omit the "esm/vs/" prefix.
import * as monaco from 'monaco-editor/editor/editor.api'
import EditorWorker from 'monaco-editor/editor/editor.worker?worker'
import 'monaco-editor/languages/definitions/yaml/register.js'
import 'monaco-editor/languages/definitions/python/register.js'
import { loader } from '@monaco-editor/react'

self.MonacoEnvironment = {
  getWorker() {
    return new EditorWorker()
  },
}

loader.config({ monaco })
