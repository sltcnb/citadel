# Citadel Improvement Roadmap

Prioritized against the current codebase (June 2026). Effort estimates assume one developer familiar with the stack.

## Now — quick wins (hours, implemented)

| # | Item | Area | Why cheap |
|---|------|------|-----------|
| 1 | AI agent feedback (thumbs up/down per run) | Autopilot | Post-run endpoint pattern already exists (`flag_evidence`); Redis storage |
| 2 | MITRE ATT&CK context in agent reasoning | Autopilot | `mitre.id`/`mitre.tactic` already indexed; inject case technique summary into agent intro |
| 3 | Module recommendation per case | Modules | Registry YAMLs already declare `input_extensions`; reverse-map vs artifact types present in case |
| 4 | Natural-language search (NL → Lucene) | Features | LLM provider layer exists (`_call_llm_with_system`); field catalog already discoverable per case |

## Implemented (batch 2)

| Item | Area | Notes |
|------|------|-------|
| Module run cancel | Modules | Co-operative Redis flag (`fo:module_cancel:{run_id}`) honoured at phase boundaries; CANCELLED status; UI cancel button |
| Webhook triggers on rule match | Features | `api/routers/webhooks.py` admin CRUD + test; processor fires Slack/Teams-compatible POST after auto detection run |

## Already existed — explorer false-gaps (verify before building anything here)

- **NL search**: `/search/ai-assist` + Timeline integration
- **MISP auto-sync**: CTI scheduler polls all feed types incl. `misp` every interval (`cti.py:163`)
- **VirusTotal config**: admin VT key endpoints + malwoverview module

## Implemented (batch 3)

| Item | Area | Notes |
|------|------|-------|
| module_completed webhook event | Features | Shared `processor/tasks/_webhooks.py` sender; fires when a module finds hits; event checkboxes in Settings |
| Report templates | Features | `fo:report_template` — title prefix, branding header/footer (Markdown), section toggles, flagged cap; admin UI in Settings → System |

## Re-scoped after code review

- **Progressive module result streaming**: dropped. Most modules are subprocess binaries — results only exist after execution; the parse→index gap is seconds. SSE log streaming already covers the wait. Revisit only if a long-running incremental module appears.
- **Server-side PDF**: deferred. WeasyPrint drags cairo/pango into the API image; browser print-to-PDF of the HTML report covers the need.

## Next — high value

| Item | Area | Notes |
|------|------|-------|
| Agent conditional branching / auto-pivot | Autopilot | Generalize stale-nudge into branch declarations (2–3d) |
| Graph visualization (process tree) | Features | Cytoscape/D3 dependency + reuse process-tree reconstruction |

## Later — medium projects (2–4 weeks each)

| Item | Area | Notes |
|------|------|-------|
| Module chaining / pipelines | Modules | DAG executor via Celery chains; hard parts: result-type matching between modules, failure cascading |
| Conditional branching / auto-pivot in agent | Autopilot | Generalize existing stale-nudge into explicit branch declarations |
| Multi-agent orchestration (Triage/DeepDive/Reporting) | Autopilot | Requires decomposing monolithic `_agent_run()` + prompt; tool dict is already plugin-style, helps |
| Interactive graph visualization (process/network) | Features | Add Cytoscape/D3 (no charting lib bundled today); process-tree reconstruction logic reusable |
| Persistent comments + @mentions | Features | Collab SSE exists but ephemeral; needs durable Redis/ES schema + notifications |
| VirusTotal/Shodan IOC enrichment | Features | API clients + caching + credential vault |
| Investigation templates (store successful agent paths) | Autopilot | Transcript persistence exists; needs replay/parameterization layer |

## Distant / reconsider — cost outweighs value today

- **K8s module sharding** (3–4w, per-chunk resource-limit risk; Hayabusa/YARA already parallelize internally)
- **Module marketplace + revenue sharing** (product/legal scope, not engineering)
- **Federated learning, RLHF threshold auto-tuning** (needs data volume that doesn't exist yet)
- **Visual drag-and-drop workflow builder** (build pipeline backend first; UI later)
- **Real-time co-editing (Google Docs-style)** (CRDT complexity; SSE collab covers most of the value)
- **Attack progression prediction, anticipatory prefetch** (research-grade; revisit after feedback loop collects data)

## Architecture notes feeding these decisions

- Agent core: `api/routers/llm_config.py:1752-3848` — single generator loop, plugin-style `AGENT_TOOLS` dict, SSE + polling both supported, transcripts persisted in Redis (last 10 runs/case).
- Modules: Celery `modules` queue → `processor/tasks/module_task.py`; custom modules sandboxed via subprocess rlimits (`_module_sandbox.py`); no chaining, no cancel, SSE log stream only.
- Frontend: React 18 + Tailwind, no charting library — all viz is custom Canvas. Any graph feature implies adding a dependency.
- Search: Lucene query_string with smart IOC auto-wildcarding (`api/services/elasticsearch.py:204-292`); facets already aggregated server-side.
