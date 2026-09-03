# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Analyst investigation suite

- **Alert-triggered auto-investigation** — fired detection rules spawn scoped Pilot investigations (ranked by severity × match count); analysts open pre-triaged alerts with a verdict instead of raw rows.
- **Entity graph** — host ↔ user ↔ IP relationship view for spotting lateral movement at a glance.
- **Baseline / rare-artifact stacking** — least-frequency-of-occurrence: surface values rare across the case but present on a target host.
- **Reverse kill-chain assembly** — from an anchor event, walk back to first access and forward to impact, tagged with ATT&CK.
- **Cross-case Pilot memory** — IOCs, TTPs, and verdicts persist across cases ("this IOC appeared in a prior case"); a continuous co-pilot surfaces un-triaged new activity.
- **Confidence-calibrated verdicts** — Pilot conclusions carry evidence-weighted confidence bands; low-confidence verdicts are flagged "needs more data".
- **Signed evidence chain-of-custody** — per-case, hash-chained artifact seals plus a court-ready, HMAC-signable custody manifest.
- **Tamper-evident audit log** — persistent, hash-chained record of every mutating request, with on-demand verification.
- **IP enrichment** — GeoIP, ASN, and reverse-DNS on public IP fields during normalization.
- **Sigma opt-out** — runtime global toggle plus per-case override (replaces the restart-only environment flag).

### Added — Browser history: collection and post-compromise pivot

Answering *"what did they browse, what did they download, and what happened to
it next"* was only actually possible on Windows. The three gaps below each broke
a different link in that chain.

- **Safari and macOS quarantine are now parsed.** Talon has always collected
  `~/Library/Safari/History.db` and
  `com.apple.LaunchServices.QuarantineEventsV2`, but neither filename was in the
  `browser` parser's handled set, so `can_handle` returned `False` and every
  macOS browsing timeline came back empty. Adds a Safari branch
  (`history_items` / `history_visits`, Apple Core Data epoch), Safari's
  `history_tombstones` — the URLs someone *deleted* from history, which Chrome
  does not retain at all — and the LaunchServices quarantine database, which
  records the download provenance of every quarantine-aware app: the agent that
  wrote the file, the URL it came from, the page the user was on, and the
  sender for a mail or message attachment. Quarantine survives the browser's own
  history being cleared, which makes it the first place to look for where a file
  came from. Column sets vary by macOS release, so it is read through
  `PRAGMA table_info` rather than a fixed schema.
- **Linux browser collection is a first-class category.** Browser artifacts were
  reachable only through `user_artifacts`, which was never exposed in Talon's
  capability manifest — so the Collector UI could not select it and it was not in
  the Linux defaults. There is now a `browser` category, in the defaults,
  covering Chrome, Chromium, Edge, Brave, Opera, Vivaldi, Firefox, Thunderbird
  and Tor across **native XDG, Snap and Flatpak** paths (the same browser
  installed two ways keeps two independent profile trees, and on Ubuntu the one
  actually used is usually the Snap), every user and every profile, with the same
  artifact set as the Windows collector plus `profiles.ini` and session-restore
  state.
- **macOS collected only the `Default` Chromium profile.** Every secondary
  profile was silently dropped. Now enumerates all of them, across Chrome,
  Chromium, Edge, Brave, Opera, Vivaldi and Arc, and adds Firefox's
  Flatpak/Thunderbird/Tor profile roots.
- **Browser events reach ECS.** `browser` had no entry in Rosetta's field map, so
  every browser event fell through to the `default` spec — no `event.category`,
  no `url.*`, no `file.*`. A downloaded payload therefore could not be joined to
  the prefetch / MFT / Sysmon evidence of it being executed, which is exactly the
  question "what did the malware do after it landed" asks. Browser events now map
  to `web`/`access` with `url.full`, `file.path`, `file.name`, `file.size` and
  the writing agent as `process.name`.
- **`url.full` is decomposed during normalization.** A field map can only copy
  values, so an artifact that records a whole URL yielded nothing queryable by
  host. `url.scheme` / `url.domain` / `url.port` / `url.path` / `url.query` /
  `url.extension` are now derived when absent, so one indicator — a C2 domain —
  matches across browser, DNS, Zeek and Suricata evidence. Applies to every
  artifact type carrying `url.full`, not just browsers.
- **Five detection rules over the new data** (`16_browser_forensics.yaml`):
  payload quarantined by a non-browser agent (a shell, interpreter or
  command-line fetcher wrote the file — it was pulled by something being driven,
  not clicked), download from a bare IP address (the fetch skipped DNS entirely),
  browser navigated directly to an IP, Safari history entries deleted, and
  quarantined email/message attachment.

### Fixed

- **A downloaded fo-uploader package shipped with no credentials.** In
  credentials mode the injector searched for column-aligned placeholders
  (`ENDPOINT   = ""`) while `fo_uploader.py` had been reformatted to
  single-space assignments with trailing comments, so every `str.replace` missed
  silently: the download succeeded, then the script exited with *"Script is not
  configured. Download a fresh copy from ForensicsOperator → Collector"* —
  sending the operator back to the page that had just produced it. Presigned
  mode was unaffected only because `PRESIGNED_URLS = []` still matched
  byte-for-byte. Injection now matches the *assignment* rather than its
  formatting (spacing and the per-field comments survive), and a missing
  placeholder raises instead of shipping an unconfigured package. The
  regression guard executes the injected assignments rather than substring
  matching, which is the only assertion that would have caught this.
- **`browser.filename` held a whole path for every Windows download.** The
  Chromium downloads parser took the basename with `Path(target_path).name`,
  which splits on the separator of the host *running the parser* — so a Windows
  `C:\Users\…\inv.exe` came back intact on the Linux worker and every query or
  report field keyed on the filename missed. Artifacts are parsed on a different
  OS than they were collected on, so the split is now separator-agnostic.
- **Firefox downloads had no destination path.** Chromium supplies
  `target_path` directly; Firefox only ever records it as a `file://` URI in the
  `downloads/destinationFileURI` annotation, which was stored as opaque text.
  It is now decoded into `target_path` and `filename`, which is what lets the
  "downloaded an executable" and download-joined-to-execution queries see
  Firefox at all.

### Added

- **Autopilot evaluation harness** (`tools/pilot/eval/`) — scores an agent run against a scenario rubric on evidence recall, citation grounding (do the fo_ids it cites actually exist?), verdict, ATT&CK coverage, termination and wasted steps. `_AGENT_PROMPT` had grown to 344 lines, much of it past failures encoded as instructions that could never be evaluated and therefore never removed; this is the missing feedback loop. The scorer is pure stdlib so it is testable without an LLM or Elasticsearch, live runs can be saved and re-scored offline for a deterministic baseline, and both the scorer's 22 tests and the scenario validator gate in `scripts/run_tests.sh`. Ships three scenarios: an unambiguous finding, evidence that cannot be found because the artifact class was never collected (where "inconclusive" is the only honest answer), and instructions embedded in a log line telling the agent to conclude benign.
- **Correlation detection rules** — a rule can now express *"one entity showed an unusual amount of variety"* instead of only `count >= threshold`, which is what separates a password spray from every failed login in the case:
  ```yaml
  correlation:
    group_by: network.src_ip                     # the entity that must be common
    distinct: evtx.event_data.TargetUserName     # the thing that must be varied
    min_distinct: 20
    window: 15m                                  # optional; stops slow churn accumulating
  ```
  `group_by` may be omitted for a case-wide question. Ships with password-spray (many accounts ← one source) and credential-stuffing (one account ← many sources) rules. Verified against Elasticsearch 8.13: on a corpus mixing a 25-account spray with 40 failures against a single account, 30 accounts spread over 20 hours, and machine-account noise, a plain `threshold: 10` matched 95 events and could not tell them apart, while the correlation rule qualified only the spraying source.
- **Delete module run results** — a module run can be removed from the case (or the standalone malware view) along with everything it produced: its indexed detections and findings, its results file and artifacts in object storage, and its Redis record. A one-click "Delete N failed" clears out every failed run at once; runs still pending or running are refused until cancelled.

### Changed

- Case toolbar consolidated into grouped **AI / Detect / Investigate / Case** menus; every case panel has an inline "How to use" help block and a responsive, full-width-on-mobile layout.
- Faster first load — route-level code-splitting cuts the main bundle from ~816 kB to ~64 kB.

### Security

Remediation pass over the CVSS ≥ 8.0 findings from the 2026-09-01 VVAH scan.
Several of these change deployment defaults — see **Breaking** below.

- **Evidence store cannot run on default credentials.** `MINIO_ACCESS_KEY` /
  `MINIO_SECRET_KEY` no longer default to `minioadmin` in code, in
  `.env.example`, or in `foctl`'s manifest rendering; the API refuses to start
  on an unset or `minioadmin` value (override:
  `CITADEL_ALLOW_DEFAULT_MINIO_CREDS=true`, dev only). `foctl` generates
  strong credentials for docker mode too, and heals an existing `.env` that
  still carries `minioadmin`.
- **Object-store TLS is configurable and on by default.** Every MinIO client
  (api, ingest / module / harvest workers, module sandbox, dd_image plugin)
  now reads `MINIO_SECURE` instead of hardcoding `secure=False`. The shipped
  in-cluster manifests and compose files opt out explicitly, so plaintext is
  now a visible choice rather than the only behaviour.
- **Plugin loading is integrity-gated.** Loading a plugin executes it, and the
  loaders pick candidates by filename glob off a shared writable volume.
  Group/world-writable plugin files are now refused outright, and
  `PLUGIN_TRUST_MANIFEST` enforces a fail-closed `path → sha256` allowlist
  held outside the volume. Every load is logged with its digest.
- **Kubernetes API calls fail closed without the cluster CA.** `_k8s_request`
  no longer falls back to `CERT_NONE` when the CA bundle is missing — that
  handed the pod's service account token to whatever answered on
  `kubernetes.default.svc`.
- **MFA challenge tokens are single-use.** `decode_mfa_challenge` now honours
  the revocation list and `/auth/login/totp` revokes the challenge on success,
  matching the password-change path. A captured challenge was previously
  replayable for its full 5-minute TTL.
- **Collector uploads no longer downgrade TLS on their own.** A certificate
  that fails to verify aborts the upload instead of silently retrying
  unverified; `--insecure-tls` / `FO_INSECURE_TLS=1` is required to accept an
  unauthenticated endpoint. An interceptor could previously force the
  downgrade just by presenting a bad certificate.
- **XXE / entity-expansion hardening for evidence XML.** New
  `babel.safe_xml` refuses entity declarations; the Android `packages.xml` and
  WiFi-config parsers use it. A crafted file could otherwise expand to
  gigabytes inside the processor.
- **CSV formula injection neutralised at the export boundary.** Cell values
  beginning `= + - @` (or tab/CR) are quote-escaped in
  `/export/csv`, so an ingested log line cannot become a live formula in the
  analyst's spreadsheet. The stored evidence is left byte-faithful.
- **Privileged image-pruner CronJob is no longer deployed by default.** It
  runs privileged with a hostPath mount of `/` — a container-escape primitive.
  Opt in with `maintenance.image_pruner: true`; kubelet image GC is the
  recommended alternative.
- **Frontend container runs unprivileged.** `nginxinc/nginx-unprivileged` on
  port 8080 as uid 101, with no added capabilities; the pod no longer mounts a
  Service Account token it never used, and the API pod runs with a read-only
  root filesystem.
- **HTTPS is always on for the compose proxy.** `nginx.prod.conf` serves
  `:443` with HSTS and redirects `:80`; `nginx/tls-bootstrap.sh` generates a
  self-signed certificate when none is mounted, so "no certificate yet" no
  longer means "no encryption". Ingress gains an HSTS middleware and a TLS 1.2
  floor; the frontend's security headers are re-declared per `location` (nginx
  replaces, never merges, `add_header` sets).
- **Processor sandbox is a deliberate choice.** The Helm chart fails to render
  unless `processor.runtimeClassName` is set or
  `processor.allowUnsandboxedModules=true` acknowledges the risk.
- **Deploy-time guards.** `foctl` refuses to apply a manifest still containing
  an unsubstituted `__FO_*__` placeholder (which would push the literal
  placeholder into the cluster as a Secret value), and warns while datastore
  traffic is plaintext, the evidence StorageClass is unpinned, or the
  processor has no sandbox runtime.
- **Harvest paths are confined.** `mounted_path` is a worker-side filesystem
  path and the worker reads whatever it is handed, so case access alone did not
  stop an analyst harvesting `/etc` or `/root`. It must now normalise inside
  `HARVEST_MOUNT_ROOTS` (default `/mnt,/data`).
- **CTI feeds cannot be MITM'd.** The `verify_ssl` opt-out is removed — feed
  data becomes detection logic, so an unauthenticated peer must not influence
  it. DNS-rebinding SSRF is closed by pinning the connection to the address
  that validation actually checked, while Host/SNI keep the hostname so
  certificate verification still applies.
- **Login rate limiting is race-free.** A concurrency gate charges in-flight
  attempts against the same limit, so a parallel burst can no longer all read
  the same pre-limit failure count and pass together. Successful logins still
  release their slot, so a shared NAT is not throttled by its own successes.
- **TOTP replay protection fails closed.** A Redis error now refuses the code
  instead of accepting one that could be replayed for its ~90s window. This
  costs nothing in availability: user records live in Redis, so an outage has
  already stopped every login before that point.
- **Group administration is tenant-scoped.** `users.manage` meant "may
  administer groups", not "every tenant's groups" — `group_id` went from the
  URL straight into the store call. List/update/delete are now scoped, and a
  company-limited manager cannot reach an installation-wide group or widen one
  beyond their own access.
- **Permission changes take effect immediately.** Group mutations bump a
  generation counter that every worker's identity cache validates against, so
  an edited or removed group no longer leaves stale permissions live for the
  cache TTL.
- **Elasticsearch bulk indexing no longer drops evidence silently.** `_bulk`
  answers HTTP 200 even when individual documents are rejected; those were
  logged and swallowed, so an ingest job reported success while events were
  missing. It now raises `ESBulkPartialFailure`, naming each dropped document.
- **BitLocker recovery keys stay out of object storage.** The S3 bootstrap
  packaged the key into the `config.json` it uploads, behind a presigned URL
  valid for up to 168 hours with best-effort cleanup. The key is injected into
  the bootstrap script instead and reaches the collector as `--bitlocker-key`
  at run time.
- **Query and pattern cost is bounded.** User-supplied Lucene carries an
  explicit `max_determinized_states` and a length cap; watchlist regexes,
  Sigma `re` modifiers and Anvil grep patterns refuse catastrophic
  nested-quantifier shapes, and grep's per-file budget dropped 60s → 15s. A
  timed-out grep is now reported as UNKNOWN rather than as zero matches.
  Deliberately *not* done: escaping Lucene metacharacters, which would have
  deleted `field:value` / boolean / wildcard search entirely.
- **Zip-slip guard on Python embed extraction** — archive member names with
  traversal or absolute paths are dropped rather than written out.
- **Chunked upload assembly is serialised** with an `flock` around the
  read-check-append-write, closing a TOCTOU that could double-append a chunk
  across threads or workers.
- **License limits are enforced atomically** — count-check-create runs under a
  Redis lock, so concurrent creates cannot land at cap+1.
- **Notes export is sanitised** and the link toolbar refuses any scheme but
  `http`/`https`/`mailto`, so a `javascript:` URL can neither be inserted nor
  survive into the export window.
- **Upload filenames are sanitised before use** — they reached `logger.error`
  raw (CR/LF log forging) *and* were used as a `mkstemp` suffix, where a `/`
  is joined into the path and escapes the temp directory. The latter was not
  in the scan.
- **XXE/entity hardening extended** to the WER parser alongside Android.
- **Talon never downgrades TLS on its own** — the multipart probe and the
  execution-log upload (previously unconditionally `CERT_NONE`) now verify,
  and the whole collector honours one `--insecure-tls` opt-in.
- **Pilot scenario text is structurally defanged** — code fences and role tags
  cannot close the prompt's own structure, including where the stored scenario
  is re-embedded into the report-polish prompt. Wording is left intact, since
  an analyst legitimately writes "ignore the backup noise".
- **Collector contract documents chunk ownership** — `Chunk` carries a
  case-scoped `upload_token` (field 7) and the proto now states that
  `session_id` is a correlation handle the server must never use to select
  storage.
- Third-party GitHub Actions pinned to full commit SHAs
  (`trivy-action@master` → `ed142fd` in both workflows, `sbom-action@v0` →
  `3ad7283`).
- Traefik `readTimeout: 0` replaced with bounded `600s` + `idleTimeout: 180s`
  (Slowloris).
- Multi-tenant access control enforced on all case-scoped endpoints (company isolation).
- Prompt-injection guardrails on the Pilot agent — evidence is treated as untrusted data, never instructions.
- Authentication fails closed when disabled without an explicit opt-in; forced password rotation off the default; login rate-limiting; short-lived tokens for streaming.
- Secrets (CTI API keys, BitLocker recovery keys) redacted from API responses; SSRF-guarded threat-intel fetches.

### Breaking

- **MinIO credentials are now required.** An existing deployment with
  `MINIO_ACCESS_KEY=minioadmin` will not start. `./foctl deploy` generates and
  persists strong credentials (and rotates a `minioadmin` value out of an
  existing `.env`); for a hand-managed deployment, set both variables. MinIO's
  root user comes from the same variables in compose, so rotating them keeps
  existing bucket data reachable.
- **`MINIO_SECURE` now defaults to `true`.** The shipped manifests and compose
  files set it to `false` explicitly. A hand-rolled deployment against a
  plain-HTTP MinIO must set `MINIO_SECURE=false` or the client will fail to
  connect.
- **The frontend container listens on 8080, not 80.** The k8s Service maps
  80 → 8080 so the Ingress is unchanged, but a custom reverse proxy pointing
  at the container port needs updating (`nginx/nginx.prod.conf` already does).
- **The compose proxy publishes 443.** Set `PROXY_TLS_PORT` if 443 is taken.
  Traffic to `:80` is now redirected, so a front proxy that forwards plain
  HTTP to `:80` should mount `nginx/nginx.behind-proxy.conf` instead.
- **The Helm chart fails to render** unless `processor.runtimeClassName` names
  an installed sandbox RuntimeClass or `processor.allowUnsandboxedModules` is
  `true`.
- **The image-pruner CronJob is no longer applied** unless
  `maintenance.image_pruner: true` is set in `config.json`.
- **CTI feeds no longer accept `verify_ssl`.** A feed that relied on disabling
  certificate verification will now fail to pull; add the server's CA to the
  container trust store instead.
- **Harvests are confined to `HARVEST_MOUNT_ROOTS`** (default `/mnt,/data`).
  Set it if evidence is mounted elsewhere on the worker.
- **Ingest fails visibly on rejected documents.** A persistent mapping
  conflict that previously produced a "successful" job with missing events now
  fails the job. Fix the mapping, or the events stay unindexed either way —
  the difference is whether anyone is told.

### Fixed

- **Evidence-seal test suites run again.** Both were failing or excluded with
  "not reliable against fakeredis"; they were never flaky. The seal lock is a
  Lua spin-lock and plain `fakeredis` answers `EVAL` with "unknown command",
  so CI installs `fakeredis[lua]` and the `--ignore` is gone. 31 tests
  covering the chain-of-custody seal are back under gate.

- **Module runs no longer die with an unexplained `SoftTimeLimitExceeded()`** — Celery's soft task limit was 1 h while the per-parser wall budget was 2 h and Hayabusa's own subprocess timeout was also exactly 1 h, so any long EVTX run could only ever be killed by Celery, and that exception carries no message. Limits are now ordered (per-tool < parser < soft < hard ≤ broker visibility) and env-tunable (`CELERY_SOFT_TIME_LIMIT`, `CELERY_TIME_LIMIT`, `HAYABUSA_TIMEOUT_SEC`), a startup guard logs any inversion, and a timed-out run records which limit it hit and which knob to raise instead of a blank error.
- **Every detection rule carries a severity, and the rule corpus is now a blocking CI gate** — 94 native rules had no `level`, so nothing could rank them in the UI, order them in the report, or prioritise them for auto-triage; 91 also gained ATT&CK technique tags. Severities are assigned conservatively: *attempt* signals that are constant internet background noise (Log4Shell, LFI/RFI, command injection) are `high` rather than `critical`, and anything a sysadmin or EDR agent does routinely (Run-key writes, `curl | sh`, kernel-module loads, lsass handle opens, cloud IAM administration) is capped below the top band — inflating severity is how an alert queue stops being triaged. `sigil_validate.py` now runs in `scripts/run_tests.sh`, failing the build on a rule that cannot fire, has no severity, or has a malformed correlation block.
- **Every detection rule can now actually fire** — 78 of 231 native rules returned zero hits on every case regardless of the evidence, while reading as coverage. Two independent causes: wildcard patterns straddling a token boundary on an analyzed field, and 13 rules referencing fields no parser emits (`registry.key` → `key_path`, `lnk.target` → `target_path`, `mft.full_path` → `file_path`, `syslog.message` → `raw_message`, `prefetch.path` → nothing). The index template now carries a `.ci` subfield (keyword + lowercase normalizer) on the fields detections substring-match, so punctuation survives *and* patterns stay case-insensitive — neither `text` (token-split) nor `.keyword` (case-sensitive, and `ignore_above: 1024` drops real EVTX messages) works alone. **Applies to newly created indices; existing cases keep their mapping until reindexed.**
- **Malformed rule queries are no longer silent** — an unescaped `/` makes `query_string` read `/.../` as a regex, an unescaped `:` is the field separator, and a quote or bracket inside a wildcard is rejected outright: Elasticsearch 400s the whole query, which the evaluator reported as "no match". A rejected query now raises, because a rule that 400s on every run was indistinguishable from one that found nothing. Five such rules were found this way (plus a typo'd `message::`). New `sigil_esvalidate.py` asks Elasticsearch to parse every rule query — it catches this class, which a static linter provably cannot.
- **Rule severity and ATT&CK tags reached the library at all** — the YAML loader built each library entry from a fixed key list that omitted `level` and `mitre`, so all 133 native rules that declare a severity had it silently discarded on load. The UI's level pills, report ordering and alert auto-triage prioritisation therefore had nothing to rank by. Both fields now survive, alongside an optional `correlation` block.
- **Three authentication rules that could never fire** — `message:*LogonType\:10*` and friends returned zero hits on every case (the analyzer splits `LogonType:10` into `[logontype, 10]`, and a wildcard matches one token). They now read the parsed `evtx.event_data.LogonType` field, and the NTLM rule excludes machine accounts since computer-to-computer NTLM is routine on a domain. Verified firing against Elasticsearch 8.13.
- **All five rule-evaluation paths share one evaluator** — case rules, the global library, single-rule runs and LLM analysis each built their own Elasticsearch body and threshold check, and had already drifted: only two set `track_total_hits`, so in the others a count above 10 000 was silently capped and a rule with a higher threshold could never fire.
- **Modules now get the CPU they were allocated** — Hayabusa (Rust/rayon) and other pooled parsers sized their thread pools from `os.cpu_count()`, which reports the *host's* cores and ignores the container's cgroup quota: a `cpus: 2` worker on a 16-core host spawned 16 threads to share 2 cores' worth of quota, so the cgroup was throttled every period and a Sigma sweep ran far slower than a correctly-sized one while looking CPU-starved. The per-parser budget is now derived as (cgroup quota ÷ worker concurrency) and exported as `RAYON_NUM_THREADS`/`OMP_NUM_THREADS`/…, overridable with `PARSER_THREADS`. The module worker's defaults also rise from 2 CPU/4 GB to 4 CPU/8 GB (`MODULE_CPU_LIMIT`, `MODULE_MEM_LIMIT`) and its concurrency drops 2 → 1, since one internally-parallel binary using the whole quota beats two splitting it at half the peak memory.
- **Two detection rules that fired on routine activity are tuned** — `4648` (explicit-credential logon) matched every scheduled task with stored credentials, every mapped drive and every service logon; `4672` (special privileges) fires for SYSTEM at every boot. Both now exclude machine accounts and the well-known service principals, and 4648 requires repetition rather than a single event. Verified against Elasticsearch 8.13: 6 → 2 and 5 → 3 hits on a noise/signal corpus, with the true positives retained.
- **Detection rules that could never fire are now caught in CI** — `sigil_validate.py` rejects wildcard patterns that cannot match an analyzed field (on a `text` field each wildcard matches a single token, and the analyzer has already split on `-\/$=@%+&|,;!?()[]{}<>~^"'` and on `:` between a letter and a digit). Verified against Elasticsearch 8.13 with the real index template. `sigil_inventory.py` additionally generates the field inventory parsers actually emit, so a rule referencing a non-existent field is detectable rather than silently reporting zero hits forever.
- **Threat intel no longer matches your own estate** — `cti_match` derives internal/non-routable status from the indicator value (RFC1918, loopback, link-local, CGNAT, multicast, reserved, `.local`/`.corp`/… hostnames) instead of trusting the flag written at feed-ingest time, and suppresses internal, own-network and allowlisted indicators from the timeline by default (`include_internal=true` keeps them). Private IPs are no longer reported as HIGH threat-intel detections.
- **Reports show the AI work that was actually done** — the exported report used to read `case:{id}:ai:report` alone, so a case with a risk assessment, autopilot runs or investigation sessions still printed "No AI narrative". It now falls back to an assessment assembled from those artifacts, labelled as derived rather than as a written report.
- **AI report evidence accuracy** — the ingested-files provenance section matched a job status the pipeline never writes (always "None."), module detections reached the model unnamed (`rule_title` was never read), and runs that failed were omitted entirely, letting "nothing found" read as "nothing there". Failed/incomplete runs are now listed explicitly as having produced no coverage.
- **Cuckoo runs no longer succeed falsely** — submission errors and analysis timeouts were emitted as low-severity "detections" on a COMPLETED run, so failures flowed into reports as sandbox evidence. Errors go to stderr, a run where nothing was analysed fails, and a task that never reaches `reported` no longer has its empty report scored as clean.
- Module runs record a `created_at`, so a run that failed at dispatch still shows a timestamp and the list keeps launch order instead of falling back to the random run id; run times display seconds so a batch launched together is distinguishable.
- Correct detection counts above 10 000; surfaced previously-silent rule failures; fixed an empty MITRE report section; atomic archive restore; resolved concurrent-edit races on rule/feed/config storage.
- Heavy work (intel polling, malware upload, log streaming, chunked ingest) moved off the request path for a more responsive API.
- **Talon collector reliability** — the harvester now tees a full execution log to `<output>.collector.log` from the first line and uploads it to S3 alongside the archive (second presigned URL), so a crash, an OOM/IO kill, or a `SIGTERM` still leaves a post-mortem. Signal handlers and a wrapping `try/finally` guarantee the log ships on any exit. The collector refuses to upload an empty (~22-byte stub) archive — it ships the log instead and exits non-zero. Free space on the output and staging volumes is logged up front (a full disk is the usual cause of truncated archives and mid-run kills), packaging detects `ENOSPC` and stops with a clear "DISK FULL" message instead of a silently truncated ZIP, and a dead-box `cryptsetup --version` probe can no longer hang the unlock.

## [1.0.0] — Initial release

End-to-end DFIR platform: **acquire → ingest → parse → normalize → detect → analyze → enrich → investigate → report**, built as a suite of standalone tools (Talon, Sluice, Babel, Rosetta, Sigil, Anvil, Augur, Pilot, Scribe) composed by Citadel over shared contracts.

- **Acquisition** — Talon live + dead-box collection (Windows/Linux/macOS), BitLocker decryption, resumable encrypted uploads, gRPC remote agent (mTLS).
- **Ingestion & parsing** — 40+ forensic formats auto-detected (EVTX, MFT, Registry, Prefetch, PCAP, cloud audit logs, mobile, browsers, AV/EDR); recursive archive + disk-image extraction; custom-parser SDK.
- **Normalization** — `ForensicEvent → ECS v8` + OSSEM/ATT&CK enrichment.
- **Detection** — 1 600+ built-in rules (Sigma + ES queries), Sigma→ES conversion, ATT&CK coverage matrix.
- **Analysis** — Hayabusa, YARA, Volatility3, capa/FLOSS, oletools, RegRipper, CTI matching, in sandboxed DAG pipelines.
- **Threat intel** — STIX/TAXII, MISP, OTX/URLhaus/AbuseIPDB/Shodan/GreyNoise enrichment with confidence scoring.
- **Investigation & reporting** — autonomous LLM Pilot agent; HTML/PDF/STIX/MISP reports.
- **Platform** — cases, timeline, full-text + faceted search, multi-tenancy, RBAC, JWT auth, tiered licensing.
- **Deploy** — Docker Compose, Helm chart, and Kubernetes manifests; Prometheus metrics, health probes, structured logs.
