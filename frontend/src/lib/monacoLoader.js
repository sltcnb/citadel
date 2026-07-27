// Pins which Monaco build the browser actually loads.
//
// @monaco-editor/react does not bundle the editor: it fetches it at runtime
// through @monaco-editor/loader, whose default CDN URL is hardcoded to whatever
// monaco-editor version *that loader release* shipped against (0.55.1 today) --
// completely independent of the monaco-editor version resolved in
// package-lock.json. So bumping the lockfile alone silences the scanners while
// the browser keeps executing the old build.
//
// MONACO_VERSION must therefore stay in step with the `monaco-editor` override
// in package.json. Bump both together, or the runtime silently drifts back
// behind the lockfile.
//
// Import this module for side effects before mounting any <Editor>; config()
// must run before the loader's first init(). It is idempotent in practice
// because every Editor call site imports this same module instance.
import { loader } from '@monaco-editor/react'

export const MONACO_VERSION = '0.56.0'

loader.config({
  paths: { vs: `https://cdn.jsdelivr.net/npm/monaco-editor@${MONACO_VERSION}/min/vs` },
})
