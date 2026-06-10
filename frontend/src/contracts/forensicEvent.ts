// AUTO-GENERATED from contracts/forensic_event.schema.json — do not edit by hand.
// Regenerate: scripts/contracts_codegen.py
// Contract: https://citadel.dfir/contracts/forensic_event/v1.json

/** ForensicEvent */
export interface ForensicEvent {
  /** Event time, ISO 8601 with Z (UTC). */
  timestamp: string;
  /** Human-readable summary of the event. */
  message: string;
  /** Routing key from the ~90-entry artifact-type taxonomy (e.g. windows_event, prefetch, syslog, docker_event). */
  artifact_type?: string;
  /** What the timestamp means (e.g. 'creation', 'last_run', 'logon'). */
  timestamp_desc?: string;
  /** Original parsed record. REQUIRED for structured artifact types; preserves fidelity for re-mapping. */
  raw?: unknown | string;
  /** OS classification of the source artifact. */
  os?: "windows" | "linux" | "macos" | "mobile" | "cross" | "cloud" | "network";
  /** Path/name of the artifact this event was parsed from. */
  source_path?: string;
  /** Babel parser id that produced this event. */
  parser?: string;
  [key: string]: unknown;
}
