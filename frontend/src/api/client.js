const BASE = '/api/v1'

const TOKEN_KEY = 'fo_token'

export function getToken()           { return localStorage.getItem(TOKEN_KEY) }
export function setToken(t)          { localStorage.setItem(TOKEN_KEY, t) }
export function clearToken()         { localStorage.removeItem(TOKEN_KEY) }
export function isAuthenticated()    { return !!getToken() }

// Called by App when the server responds 401 — clears state and reloads to /login
function _handle401() {
  clearToken()
  // Hard reload so React router re-evaluates the auth gate cleanly
  window.location.href = '/login'
}

async function request(method, path, body, options = {}) {
  const url     = `${BASE}${path}`
  const token   = getToken()
  const headers = body instanceof FormData
    ? {}
    : { 'Content-Type': 'application/json' }

  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(url, {
    method,
    headers,
    body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined,
    ...options,
  })

  if (res.status === 401) {
    _handle401()
    // Return a never-resolving promise so callers don't continue after redirect
    return new Promise(() => {})
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    const detail = err.detail
    // Pydantic v2 validation errors return detail as an array of {msg, loc, ...}
    const msg = Array.isArray(detail)
      ? detail.map(d => d.msg || JSON.stringify(d)).join('; ')
      : (typeof detail === 'string' ? detail : `HTTP ${res.status}`)
    throw new Error(msg || `HTTP ${res.status}`)
  }
  if (res.status === 204) return null
  return res.json()
}

function withParams(path, params) {
  const q = new URLSearchParams(params).toString()
  return q ? `${path}?${q}` : path
}

// Cases
export const api = {
  cases: {
    list:        ()           => request('GET',    '/cases'),
    get:         (id)         => request('GET',    `/cases/${id}`),
    create:      (data)       => request('POST',   '/cases', data),
    update:      (id, data)   => request('PUT',    `/cases/${id}`, data),
    delete:      (id)         => request('DELETE', `/cases/${id}`),
    getAutoRun:  (id)         => request('GET',    `/cases/${id}/auto-run`),
    setAutoRun:  (id, flags)  => request('PUT',    `/cases/${id}/auto-run`, flags),
    getSigma:    (id)         => request('GET',    `/cases/${id}/sigma`),
    setSigma:    (id, enabled) => request('PUT',   `/cases/${id}/sigma`, { enabled }),
    aiAggregate: (id, question) => request('POST', `/cases/${id}/ai/aggregate`, { question }),
    aiAnalyze:   (id)         => request('POST',   `/cases/${id}/ai/analyze`),
    aiInvestigate: (id, circumstance) => request('POST', `/cases/${id}/ai/investigate`, { circumstance }),
    aiAgent:       (id, circumstance, maxSteps) => request('POST', `/cases/${id}/ai/agent`, { circumstance, max_steps: maxSteps }),
    aiAgentFlag:     (id, runIdx)       => request('POST', `/cases/${id}/ai/agent/${runIdx}/flag_evidence`),
    aiAgentPromote:  (id, runIdx)       => request('POST', `/cases/${id}/ai/agent/${runIdx}/promote_iocs`),
    aiAgentFeedback: (id, runIdx, data) => request('POST', `/cases/${id}/ai/agent/${runIdx}/feedback`, data),
    // Background-resumable agent runs
    aiAgentStart:    (id, circumstance, maxSteps, parentRunIdx, language) =>
      request('POST', `/cases/${id}/ai/agent/start`,
              { circumstance, max_steps: maxSteps,
                parent_run_idx: parentRunIdx ?? undefined,
                language: language ?? undefined }),
    aiAgentActive:   (id)                  => request('GET',  `/cases/${id}/ai/agent/active`),
    aiAgentProgress: (id, runId, since=0)  => request('GET',  `/cases/${id}/ai/agent/progress/${runId}?since=${since}`),
    aiAgentCancel:   (id, runId)           => request('POST', `/cases/${id}/ai/agent/cancel/${runId}`),
    aiResults:   (id)         => request('GET',    `/cases/${id}/ai/results`),
    aiDeleteResults:    (id, withReport=false) => request('DELETE', `/cases/${id}/ai/results?include_report=${withReport ? 'true' : 'false'}`),
    aiDeleteReport:     (id)                    => request('DELETE', `/cases/${id}/ai/report`),
    aiDeleteAgentRuns:  (id)                    => request('DELETE', `/cases/${id}/ai/agent_runs`),
    aiDeleteInvestigation: (id, idx) => request('DELETE', `/cases/${id}/ai/investigation/${idx}`),
    aiReport:    (id, runIds) => request('POST', `/cases/${id}/ai/report`, runIds?.length ? { run_ids: runIds } : {}),
  },

  ingest: {
    upload:   (caseId, formData) => request('POST', `/cases/${caseId}/ingest`, formData),
    listJobs: (caseId, params={}) => request('GET', withParams(`/cases/${caseId}/jobs`, params)),
    getJob:    (jobId)            => request('GET',  `/jobs/${jobId}`),
    batchJobs: (jobIds)          => request('POST', '/jobs/batch', { job_ids: jobIds }),
    retryJob:             (jobId)                 => request('POST',   `/jobs/${jobId}/retry`),
    reingestJob:          (caseId, jobId, plugin) => request('POST', `/cases/${caseId}/jobs/${jobId}/reingest`, plugin ? { plugin } : {}),
    cancelCaseIngestion:  (caseId)                => request('POST', `/cases/${caseId}/ingest/cancel`),
    deleteJob:    (jobId)   => request('DELETE', `/jobs/${jobId}`),
    deleteAllJobs: (caseId) => request('DELETE', `/cases/${caseId}/jobs`),
  },

  // ── Analyst gamechangers: baseline stacking, entity graph, kill-chain,
  //    Pilot cross-case memory + co-pilot watch, signed evidence chain ─────────
  baseline: {
    fields: (caseId) => request('GET', `/cases/${caseId}/baseline/fields`),
    stack:  (caseId, field, host, maxHosts = 2) =>
      request('GET', withParams(`/cases/${caseId}/baseline/stack`, { field, host, max_hosts: maxHosts })),
  },
  graph: {
    get:      (caseId, { focus = null, limit = 50 } = {}) =>
      request('GET', withParams(`/cases/${caseId}/graph`, focus ? { focus, limit } : { limit })),
    entities: (caseId, limit = 50) => request('GET', withParams(`/cases/${caseId}/graph/entities`, { limit })),
  },
  killchain: {
    get: (caseId, { foId = null, host = null, timestamp = null, windowMinutes = 60 } = {}) => {
      const p = { window_minutes: windowMinutes }
      if (foId) p.fo_id = foId
      if (host) p.host = host
      if (timestamp) p.timestamp = timestamp
      return request('GET', withParams(`/cases/${caseId}/killchain`, p))
    },
  },
  pilot: {
    recallMemory: (kind, value) => request('GET', withParams('/pilot/memory', { kind, value })),
    seenBefore:   (caseId, values) => request('POST', `/cases/${caseId}/pilot/memory/seen`, { values }),
    watchStatus:  (caseId) => request('GET', `/cases/${caseId}/pilot/watch`),
    markReviewed: (caseId) => request('POST', `/cases/${caseId}/pilot/watch/reviewed`),
  },
  evidence: {
    seal:     (caseId, data) => request('POST', `/cases/${caseId}/evidence/seal`, data),
    seals:    (caseId) => request('GET', `/cases/${caseId}/evidence/seals`),
    verify:   (caseId) => request('GET', `/cases/${caseId}/evidence/verify`),
    manifest: (caseId) => request('GET', `/cases/${caseId}/evidence/manifest`),
  },

  search: {
    timeline: (caseId, params = {}) => request('GET', withParams(`/cases/${caseId}/timeline`, params)),
    search:   (caseId, params = {}) => request('GET', withParams(`/cases/${caseId}/search`, params)),
    facets:   (caseId, params = {}) => request('GET', withParams(`/cases/${caseId}/search/facets`, params)),
    iocs:      (caseId)              => request('GET', `/cases/${caseId}/iocs`),
    fields:    (caseId)              => request('GET', `/cases/${caseId}/fields`),
    aggregate: (caseId, params = {}) => request('GET', withParams(`/cases/${caseId}/aggregate`, params)),
    crossCase: (query, sizePerCase = 3) => request('POST', '/search/cross', { query, size_per_case: sizePerCase }),
    mitreCoverage: (caseId) => request('GET', `/cases/${caseId}/mitre/coverage`),
    anomalies:     (caseId) => request('GET', `/cases/${caseId}/anomaly`),
    report: {
      markdown: (caseId) => `/api/v1/cases/${caseId}/report.md`,
      html:     (caseId) => `/api/v1/cases/${caseId}/report.html`,
    },
    pinned: (caseId) => request('GET', `/cases/${caseId}/pinned`),
    processTree: (caseId, host) => request('GET', `/cases/${caseId}/process-tree${host ? `?host=${encodeURIComponent(host)}` : ''}`),
    whois:     (ip)                 => request('GET', `/whois/${encodeURIComponent(ip)}`),
    getEvent:  (caseId, foId)        => request('GET', `/cases/${caseId}/events/${foId}`),
    tagEvent:  (caseId, foId, tags)  => request('PUT', `/cases/${caseId}/events/${foId}/tag`,  { tags }),
    flagEvent: (caseId, foId)        => request('PUT', `/cases/${caseId}/events/${foId}/flag`),
    pinEvent:  (caseId, foId, body = {}) => request('PUT', `/cases/${caseId}/events/${foId}/pin`, body),
    pinned:    (caseId)              => request('GET', `/cases/${caseId}/pinned`),
    noteEvent: (caseId, foId, note)  => request('PUT', `/cases/${caseId}/events/${foId}/note`, { note }),
  },

  plugins: {
    list:   ()         => request('GET',  '/plugins'),
    reload: ()         => request('POST', '/plugins/reload'),
    upload: (formData) => request('POST', '/plugins/upload', formData),
  },

  tools: {
    capabilities: ()      => request('GET', '/tools/capabilities'),
    capability:   (tool)  => request('GET', `/tools/${tool}/capabilities`),
    sync:         ()      => request('POST', '/admin/tools/sync-capabilities'),
  },

  health: {
    ready: () => request('GET', '/health/ready'),
  },

  auth: {
    me:                 ()                   => request('GET',    '/auth/me'),
    streamToken:        ()                   => request('GET',    '/auth/stream-token'),
    login:              (data)               => request('POST',   '/auth/login', data),
    logout:             ()                   => request('POST',   '/auth/logout'),
    listUsers:          ()                   => request('GET',    '/auth/users'),
    createUser:         (data)               => request('POST',   '/auth/users', data),
    updateUser:         (username, data)     => request('PUT',    `/auth/users/${username}`, data),
    deleteUser:         (username)           => request('DELETE', `/auth/users/${username}`),
    changePassword:     (data)               => request('PUT',    '/auth/me/password', data),
    setUserCompanies:   (username, companies) => request('PUT',    `/auth/users/${username}/companies`, { companies }),
    totpStatus:         ()                   => request('GET',    '/auth/me/totp'),
    totpSetup:          ()                   => request('POST',   '/auth/me/totp/setup'),
    totpEnable:         (code)               => request('POST',   '/auth/me/totp/enable', { code }),
    totpDisable:        (password)           => request('POST',   '/auth/me/totp/disable', { password }),
    // RBAC — groups, permission catalog, effective access
    listGroups:         ()                   => request('GET',    '/groups'),
    createGroup:        (data)               => request('POST',   '/groups', data),
    updateGroup:        (id, data)           => request('PUT',    `/groups/${id}`, data),
    deleteGroup:        (id)                 => request('DELETE', `/groups/${id}`),
    permissionCatalog:  ()                   => request('GET',    '/permissions'),
    userEffective:      (username)           => request('GET',    `/users/${username}/effective`),
    // SSO (OIDC) — providers list; login is a browser redirect to /api/v1/auth/sso/{id}/login
    ssoProviders:       ()                   => request('GET',    '/auth/sso/providers'),
  },

  savedSearches: {
    list:   (caseId)       => request('GET',    `/cases/${caseId}/saved-searches`),
    create: (caseId, data) => request('POST',   `/cases/${caseId}/saved-searches`, data),
    delete: (caseId, id)   => request('DELETE', `/cases/${caseId}/saved-searches/${id}`),
  },

  collab: {
    publish: (caseId, type, payload = {}) => request('POST', `/cases/${caseId}/collab/event`, { type, payload }),
    recent:  (caseId) => request('GET', `/cases/${caseId}/collab/recent`),
    streamUrl: (caseId) => `/api/v1/cases/${caseId}/collab/stream`,
  },

  caseTemplates: {
    list:    () => request('GET', '/case-templates'),
    detail:  (caseId, tplId) => request('GET', `/cases/${caseId}/case-templates/${tplId}`),
    getFull: (id) => request('GET', `/case-templates/${id}`),
    create:  (data) => request('POST', '/case-templates', data),
    update:  (id, data) => request('PUT', `/case-templates/${id}`, data),
    remove:  (id) => request('DELETE', `/case-templates/${id}`),
    apply: (caseId, templateId) => request('POST', `/cases/${caseId}/apply-template?template_id=${encodeURIComponent(templateId)}`),
  },

  watchlist: {
    list:     () => request('GET',    '/watchlist'),
    add:      (entry) => request('POST', '/watchlist', entry),
    delete:   (id) => request('DELETE', `/watchlist/${id}`),
    evaluate: () => request('POST',   '/watchlist/evaluate'),
    getWhitelist: () => request('GET', '/watchlist/whitelist'),
    setWhitelist: (hostnames, ips) => request('PUT', '/watchlist/whitelist', { hostnames, ips }),
  },

  notes: {
    get:  (caseId)       => request('GET', `/cases/${caseId}/notes`),
    save: (caseId, body) => request('PUT', `/cases/${caseId}/notes`, { body }),
  },

  alertRules: {
    list:            (caseId)         => request('GET',    `/cases/${caseId}/alert-rules`),
    create:          (caseId, data)   => request('POST',   `/cases/${caseId}/alert-rules`, data),
    delete:          (caseId, id)     => request('DELETE', `/cases/${caseId}/alert-rules/${id}`),
    check:           (caseId)         => request('POST',   `/cases/${caseId}/alert-rules/check`),
    lastRun:         (caseId)         => request('GET',    `/cases/${caseId}/alert-rules/last-run`),
    reanalyzeMatch:  (caseId, ruleId) => request('POST',   `/cases/${caseId}/alert-rules/last-run/analyze/${ruleId}`),
    listLibrary:     ()               => request('GET',    '/alert-rules/library'),
    createLibraryRule: (data)         => request('POST',   '/alert-rules/library', data),
    updateLibraryRule: (id, data)     => request('PUT',    `/alert-rules/library/${id}`, data),
    deleteLibraryRule: (id)           => request('DELETE', `/alert-rules/library/${id}`),
    seedLibrary:     (replace=false)  => request('POST',   `/alert-rules/library/seed?replace=${replace}`),
    runLibrary:      (caseId, ruleTypes = []) => {
      const qs = ruleTypes.length ? ruleTypes.map(t => `rule_types=${encodeURIComponent(t)}`).join('&') : ''
      return request('POST', `/cases/${caseId}/alert-rules/run-library${qs ? '?' + qs : ''}`)
    },
    runSingleRule:       (caseId, ruleId) => request('POST', `/cases/${caseId}/alert-rules/library/${ruleId}/run`),
    runSingleCaseRule:   (caseId, ruleId) => request('POST', `/cases/${caseId}/alert-rules/${ruleId}/run`),
    importSigma:     (data)           => request('POST',   '/alert-rules/library/sigma', data),
    getLibraryRule:  (id)             => request('GET',    `/alert-rules/library/${id}`),
    generateRule:    (data)           => request('POST',   '/alert-rules/generate', data),
    generateSigmaRule: (data)         => request('POST',   '/alert-rules/generate-sigma', data),
    analyzeResult:   (data)           => request('POST',   '/alert-rules/analyze', data),
    parseSigma:      (data)           => request('POST',   '/alert-rules/sigma/parse', data),
    triage:          (caseId, limit=3) => request('POST',  `/cases/${caseId}/alert-rules/triage?limit=${limit}`),
    getTriage:       (caseId)          => request('GET',   `/cases/${caseId}/alert-rules/triage`),
  },

  export: {
    csv: (caseId, params = {}) => {
      const q     = new URLSearchParams(params).toString()
      const token = getToken()
      const auth  = token ? `_token=${encodeURIComponent(token)}` : ''
      // Build query string: params first, then token — always uses ? before first param
      const qs    = [q, auth].filter(Boolean).join('&')
      return `/api/v1/cases/${caseId}/export/csv${qs ? '?' + qs : ''}`
    },
    archivePurge:   (caseId) => request('POST', `/cases/${caseId}/purge-archive`),
    uploadArchive:  (caseId) => request('POST', `/cases/${caseId}/upload-archive`),
    restoreArchive: (caseId) => request('POST', `/cases/${caseId}/restore-archive`),
    importArchive:       (file) => { const fd = new FormData(); fd.append('file', file); return request('POST', '/cases/import/archive', fd) },
    importArchiveFromS3: (key)  => request('POST', '/cases/import/archive-s3', { key }),
    testArchiveS3:       ()     => request('POST', '/admin/archive-settings/test'),
    browseArchiveS3:     (prefix = '', delimiter = '/') =>
      request('GET', `/admin/archive-s3/browse?prefix=${encodeURIComponent(prefix)}&delimiter=${encodeURIComponent(delimiter)}`),
  },

  modules: {
    list:             ()                        => request('GET',  '/modules'),
    listSources:      (caseId)                  => request('GET',  `/cases/${caseId}/sources`),
    recommended:      (caseId)                  => request('GET',  `/cases/${caseId}/recommended-modules`),
    createRun:        (caseId, data)            => request('POST', `/cases/${caseId}/module-runs`, data),
    listRuns:         (caseId)                  => request('GET',  `/cases/${caseId}/module-runs`),
    getRun:           (runId)                   => request('GET',  `/module-runs/${runId}`),
    validateYara:     (rules)                   => request('POST', '/modules/yara/validate', { rules }),
    analyze:          (runId)                   => request('POST', `/module-runs/${runId}/analyze`),
    retryRun:         (runId)                   => request('POST', `/module-runs/${runId}/retry`),
    cancelRun:        (runId)                   => request('POST', `/module-runs/${runId}/cancel`),
    reingestArtifact: (caseId, runId, filename) => request('POST', `/cases/${caseId}/modules/${runId}/artifacts/${encodeURIComponent(filename)}/reingest`),
    logStreamUrl:     (runId)                   => `${BASE}/module-runs/${runId}/log-stream`,
  },

  webhooks: {
    list:   ()           => request('GET',    '/admin/webhooks'),
    create: (data)       => request('POST',   '/admin/webhooks', data),
    update: (id, data)   => request('PUT',    `/admin/webhooks/${id}`, data),
    remove: (id)         => request('DELETE', `/admin/webhooks/${id}`),
    test:   (id)         => request('POST',   `/admin/webhooks/${id}/test`),
  },

  studio: {
    queryTest: (caseId, query) => request('POST', '/studio/query-test', { case_id: caseId, query }),
    yaraTest:  (caseId, jobId, rules) => request('POST', '/studio/yara-test', { case_id: caseId, job_id: jobId, rules }),
  },

  sso: {
    getConfig:    ()     => request('GET', '/admin/sso-config'),
    setConfig:    (data) => request('PUT', '/admin/sso-config', data),
  },

  platform: {
    getConfig:    ()     => request('GET', '/admin/platform-config'),
    setConfig:    (data) => request('PUT', '/admin/platform-config', data),
  },

  pilotConfig: {
    getConfig:    ()      => request('GET', '/admin/pilot-config'),
    setConfig:    (data)  => request('PUT', '/admin/pilot-config', data),
    testWebSearch:(query) => request('POST', '/pilot/web-search/test', { query }),
  },

  llm: {
    getConfig:         ()     => request('GET',    '/admin/llm-config'),
    updateConfig:      (data) => request('PUT',    '/admin/llm-config', data),
    clearConfig:       ()     => request('DELETE', '/admin/llm-config'),
    testConfig:        ()     => request('POST',   '/admin/llm-config/test'),
    getUsage:          ()     => request('GET',    '/admin/llm-usage'),
    analyzeModuleRun:  (runId)     => request('POST', `/module-runs/${runId}/analyze`),
    explainEvents:     (data)      => request('POST', '/events/explain', data),
    generateRule:      (data)      => request('POST', '/alert-rules/generate', data),
    searchAssist:      (data)      => request('POST', '/search/ai-assist', data),
  },

  editor: {
    listIngesters:        ()            => request('GET',    '/editor/ingesters'),
    getIngester:          (name)        => request('GET',    `/editor/ingesters/${name}`),
    saveIngester:         (name, data)  => request('PUT',    `/editor/ingesters/${name}`, data),
    deleteIngester:       (name)        => request('DELETE', `/editor/ingesters/${name}`),
    patchIngesterPriority:(name, priority) => request('PATCH', `/editor/ingesters/${encodeURIComponent(name)}/priority`, { priority }),
    listModules:          ()            => request('GET',    '/editor/modules'),
    getModule:            (name)        => request('GET',    `/editor/modules/${name}`),
    saveModule:           (name, data)  => request('PUT',    `/editor/modules/${name}`, data),
    deleteModule:         (name)        => request('DELETE', `/editor/modules/${name}`),
    validate:             (code)        => request('POST',   '/editor/validate', { code }),
    analyzeModule:        (code, fileType) => request('POST', '/editor/analyze-module', { code, file_type: fileType }),
    // Built-in ingester plugin files (editable)
    listBuiltinIngesters: ()            => request('GET',    '/editor/builtin-ingesters'),
    getBuiltinIngester:   (name)        => request('GET',    `/editor/builtin-ingesters/${name}`),
    saveBuiltinIngester:  (name, data)  => request('PUT',    `/editor/builtin-ingesters/${name}`, data),
    deleteBuiltinIngester:(name)        => request('DELETE', `/editor/builtin-ingesters/${name}`),
    // Built-in module YAML registry files (editable)
    listBuiltinModules:   ()            => request('GET',    '/editor/builtin-modules'),
    getBuiltinModule:     (name)        => request('GET',    `/editor/builtin-modules/${name}`),
    saveBuiltinModule:    (name, data)  => request('PUT',    `/editor/builtin-modules/${name}`, data),
    deleteBuiltinModule:  (name)        => request('DELETE', `/editor/builtin-modules/${name}`),
    // Processor Python files — tasks/ and utils/ (execution engine)
    listProcessorFiles:   ()            => request('GET',    '/editor/processor-files'),
    getProcessorFile:     (name)        => request('GET',    `/editor/processor-files/${name}`),
    saveProcessorFile:    (name, data)  => request('PUT',    `/editor/processor-files/${name}`, data),
  },

  s3Multi: {
    list:         ()              => request('GET',    '/admin/s3-import-configs'),
    add:          (data)          => request('POST',   '/admin/s3-import-configs', data),
    update:       (id, data)      => request('PUT',    `/admin/s3-import-configs/${id}`, data),
    delete:       (id)            => request('DELETE', `/admin/s3-import-configs/${id}`),
    test:         (id)            => request('POST',   `/admin/s3-import-configs/${id}/test`),
    browse:       (id, prefix = '', delimiter = '/') =>
      request('GET', `/s3-import/browse/${id}?prefix=${encodeURIComponent(prefix)}&delimiter=${encodeURIComponent(delimiter)}`),
    importToCase: (caseId, configId, data) =>
      request('POST', `/cases/${caseId}/s3-import-named?config_id=${configId}`, data),
  },

  s3: {
    getConfig:    ()             => request('GET',    '/admin/s3-config'),
    setConfig:    (data)         => request('PUT',    '/admin/s3-config', data),
    clearConfig:  ()             => request('DELETE', '/admin/s3-config'),
    testConfig:   ()             => request('POST',   '/admin/s3-config/test'),
    browse:       (prefix = '', delimiter = '/') => request('GET', `/s3/browse?prefix=${encodeURIComponent(prefix)}&delimiter=${encodeURIComponent(delimiter)}`),
    importToCase: (caseId, data) => request('POST',   `/cases/${caseId}/s3-import`, data),
    importBatch:  (caseId, keys) => request('POST',   `/cases/${caseId}/s3-import-batch`, { keys }),
  },

  s3Triage: {
    status:       ()             => request('GET',    '/s3-triage/status'),
    getConfig:    ()             => request('GET',    '/admin/s3-triage-config'),
    setConfig:    (data)         => request('PUT',    '/admin/s3-triage-config', data),
    clearConfig:  ()             => request('DELETE', '/admin/s3-triage-config'),
    testConfig:   ()             => request('POST',   '/admin/s3-triage-config/test'),
    browse:       (prefix = '', delimiter = '/') => request('GET', `/s3-triage/browse?prefix=${encodeURIComponent(prefix)}&delimiter=${encodeURIComponent(delimiter)}`),
    pullToCase:   (caseId, data) => request('POST',   `/cases/${caseId}/s3-triage-pull`, data),
    importBatch:  (caseId, keys) => request('POST',   `/cases/${caseId}/s3-triage-pull-batch`, { keys }),
  },

  admin: {
    purgeOrphaned:         () => request('POST', '/admin/purge-orphaned-data'),
    wipeAll:               () => request('POST', '/admin/wipe-all-data', { confirm: 'WIPE' }),
    getArchiveSettings:    () => request('GET',  '/admin/archive-settings'),
    getReportTemplate:     ()     => request('GET',    '/admin/report-template'),
    setReportTemplate:     (data) => request('PUT',    '/admin/report-template', data),
    resetReportTemplate:   ()     => request('DELETE', '/admin/report-template'),
    updateArchiveSettings: (body) => request('PUT', '/admin/archive-settings', body),
  },

  logs: {
    services: ()                     => request('GET', '/admin/logs/services'),
    tail:     (service, params = {}) => request('GET', withParams(`/admin/logs/${service}`, params)),
    clear:    (service)              => request('DELETE', `/admin/logs/${service}`),
  },

  companies: {
    list:   ()     => request('GET',    '/companies'),
    add:    (name) => request('POST',   '/companies', { name }),
    remove: (name) => request('DELETE', `/companies/${encodeURIComponent(name)}`),
  },

  metrics: {
    dashboard: ()              => request('GET', '/metrics/dashboard'),
    history:   (limit = 480)   => request('GET', `/metrics/history?limit=${limit}`),
  },

  cti: {
    listFeeds:    () => request('GET', '/cti/feeds'),
    addFeed:      (data) => request('POST', '/cti/feeds', data),
    updateFeed:   (id, data) => request('PUT', `/cti/feeds/${id}`, data),
    deleteFeed:   (id) => request('DELETE', `/cti/feeds/${id}`),
    pullFeed:     (id) => request('POST', `/cti/feeds/${id}/pull`),
    importBundle: (data) => request('POST', '/cti/import', data),
    listIOCs:     (params = {}) => request('GET', withParams('/cti/iocs', params)),
    iocStats:     () => request('GET', '/cti/iocs/stats'),
    clearIOCs:    () => request('DELETE', '/cti/iocs'),
    purgeExpired: () => request('POST', '/cti/iocs/purge-expired'),
    matchCase:    (caseId, types) => request('POST', withParams(`/cases/${caseId}/cti/match`, types ? { types } : {})),
    indicatorEvents: (caseId, type, value, limit = 25) =>
      request('GET', withParams(`/cases/${caseId}/cti/indicator-events`, { type, value, limit })),
    getOwnNetworks: () => request('GET', '/cti/own-networks'),
    setOwnNetworks: (cidrs) => request('PUT', '/cti/own-networks', { cidrs }),
    getAllowlist: (caseId) => request('GET', withParams('/cti/allowlist', caseId ? { case_id: caseId } : {})),
    setAllowlist: (values, caseId) => request('PUT', '/cti/allowlist', caseId ? { values, case_id: caseId } : { values }),
  },

  malware: {
    uploadFile: (formData) => request('POST', '/malware-analysis/upload', formData),
    createRun:  (data)     => request('POST', '/malware-analysis/runs', data),
    listRuns:   ()         => request('GET',  '/malware-analysis/runs'),
  },

  cuckooConfig: {
    get:   ()     => request('GET',    '/admin/cuckoo-config'),
    set:   (data) => request('PUT',    '/admin/cuckoo-config', data),
    clear: ()     => request('DELETE', '/admin/cuckoo-config'),
  },

  mwoConfig: {
    get:   ()     => request('GET',    '/admin/malwoverview-config'),
    set:   (data) => request('PUT',    '/admin/malwoverview-config', data),
    clear: ()     => request('DELETE', '/admin/malwoverview-config'),
  },

  yaraRules: {
    list:         ()         => request('GET',    '/yara-rules'),
    get:          (id)       => request('GET',    `/yara-rules/${id}`),
    create:       (data)     => request('POST',   '/yara-rules', data),
    update:       (id, data) => request('PUT',    `/yara-rules/${id}`, data),
    delete:       (id)       => request('DELETE', `/yara-rules/${id}`),
    generateYara: (data)     => request('POST',   '/yara-rules/generate', data),
    exportUrl: ()         => {
      const token = getToken()
      return `/api/v1/yara-rules/export${token ? `?_token=${encodeURIComponent(token)}` : ''}`
    },
  },

  caseFiles: {
    list:        (caseId)         => request('GET',  `/cases/${caseId}/files`),
    content:     (caseId, jobId)  => request('GET',  `/cases/${caseId}/files/${jobId}/content`),
    search:      (caseId, data)   => request('POST', `/cases/${caseId}/files/search`, data),
    diskImages:  (caseId)         => request('GET',  `/cases/${caseId}/disk-images`),
    browse:      (caseId, jobId, path = '/') =>
      request('GET', `/cases/${caseId}/disk-images/${jobId}/browse?path=${encodeURIComponent(path)}`),
    // Returns a URL suitable for window.open() — token in query param since
    // browser-initiated downloads cannot set Authorization headers.
    downloadUrl: (caseId, jobId) => {
      const token = getToken()
      return `/api/v1/cases/${caseId}/files/${jobId}/download${token ? `?_token=${encodeURIComponent(token)}` : ''}`
    },
  },

  harvest: {
    listCategories: ()                         => request('GET',  '/harvest/categories'),
    listLevels:     ()                         => request('GET',  '/harvest/levels'),
    startRun:       (caseId, data)             => request('POST', `/cases/${caseId}/harvest`, data),
    getRun:         (runId)                    => request('GET',  `/harvest/runs/${runId}`),
    cancelRun:      (runId)                    => request('DELETE', `/harvest/runs/${runId}`),
  },

  collector: {
    // Legacy: single-file collect.py with embedded config (still available)
    downloadUrl: ({ platform = 'py', caseId, apiUrl, collect } = {}) => {
      const params = new URLSearchParams({ platform })
      if (caseId)  params.set('case_id',  caseId)
      if (apiUrl)  params.set('api_url',  apiUrl)
      if (collect && collect.length > 0) params.set('collect', collect.join(','))
      const token = getToken()
      if (token) { params.set('_token', token); params.set('api_token', token) }
      return `/api/v1/collector/download?${params.toString()}`
    },
    // New: fo-harvester ZIP — config.json has true/false per artifact category.
    // Input source (--path/--disk) and BitLocker key are CLI args on the target.
    packageUrl: ({ categories = [], caseName, platform, path, disk, skipProblematic, fetchPatterns, outputDir, apiUrl, caseId, apiToken, uploadMode, includePython } = {}) => {
      const params = new URLSearchParams()
      if (categories.length > 0) params.set('categories',        categories.join(','))
      if (caseName)               params.set('case_name',         caseName)
      if (platform)               params.set('platform',          platform)
      if (path)                   params.set('path',              path)
      if (disk)                   params.set('disk',              disk)
      if (skipProblematic)        params.set('skip_problematic',  'true')
      if (fetchPatterns && fetchPatterns.length > 0)
        params.set('fetch_patterns', fetchPatterns.join('\n'))
      if (outputDir)              params.set('output_dir',        outputDir)
      if (apiUrl)                 params.set('api_url',           apiUrl)
      if (caseId)                 params.set('case_id',           caseId)
      if (apiToken)               params.set('api_token',         apiToken)
      if (uploadMode)             params.set('upload_mode',       uploadMode)
      if (includePython)          params.set('include_python',    includePython)
      const token = getToken()
      if (token) params.set('_token', token)
      const qs = params.toString()
      return `/api/v1/collector/package${qs ? '?' + qs : ''}`
    },
    categories: () => request('GET', '/collector/categories'),
    pythonEmbeds: () => request('GET', '/collector/python-embeds'),
    // Admin-only: POST returns fo-uploader-presigned.zip with 3 pre-signed PUT URLs (no raw credentials).
    uploaderPresigned: async ({ filename, expiresHours = 24, count = 3 } = {}) => {
      const params = new URLSearchParams()
      if (filename)     params.set('filename',      filename)
      if (expiresHours) params.set('expires_hours', String(expiresHours))
      params.set('count', String(count))
      const token = getToken()
      const res = await fetch(`${BASE}/collector/uploader-presign?${params}`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (res.status === 401) { _handle401(); return new Promise(() => {}) }
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }))
        throw new Error(err.detail || `HTTP ${res.status}`)
      }
      return res.blob()
    },
    // Admin-only: uploads collector zip to S3, returns a tiny PS1/SH bootstrap script
    // that downloads, runs, deletes local temp, then deletes the zip from S3.
    s3Bootstrap: async ({ categories = [], caseName, caseId, apiUrl, apiToken, expiresHours = 24, platform = 'ps1', pathArg, diskArg, bitlockerKey, fetchPatterns } = {}) => {
      const params = new URLSearchParams()
      if (categories.length > 0) params.set('categories',    categories.join(','))
      if (caseName)               params.set('case_name',    caseName)
      if (caseId)                 params.set('case_id',      caseId)
      if (fetchPatterns && fetchPatterns.length > 0)
        params.set('fetch_patterns', fetchPatterns.join('\n'))
      if (apiUrl)                 params.set('api_url',      apiUrl)
      if (apiToken)               params.set('api_token',    apiToken)
      if (pathArg)                params.set('path_arg',     pathArg)
      if (diskArg)                params.set('disk_arg',     diskArg)
      if (bitlockerKey)           params.set('bitlocker_key', bitlockerKey)
      params.set('expires_hours', String(expiresHours))
      params.set('platform',      platform)
      const token = getToken()
      const res = await fetch(`${BASE}/collector/s3-bootstrap?${params}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (res.status === 401) { _handle401(); return new Promise(() => {}) }
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }))
        throw new Error(err.detail || `HTTP ${res.status}`)
      }
      return res.blob()
    },
    networkInterfaces: () => request('GET',    '/network/interfaces'),
    createIngress:     () => request('POST',   '/collector/ingress'),
    getIngress:        () => request('GET',    '/collector/ingress'),
    deleteIngress:     () => request('DELETE', '/collector/ingress'),
  },
  license: {
    info:      () => request('GET',    '/license/info'),
    refresh:   () => request('POST',   '/license/refresh'),
    install:   (key, signing_key) => request('POST',   '/license/install',
                                             { key, signing_key: signing_key || null }),
    uninstall: () => request('DELETE', '/license/install'),
  },
}
