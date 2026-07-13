// AUTO-GENERATED from contracts/brick.schema.json -- do not edit by hand.
// Regenerate: scripts/contracts_codegen.py
// Contract: https://citadel.dfir/contracts/brick/v1.json

/** brick.yaml */
export interface BrickManifest {
  /** Tool name (Talon, Sluice, …). */
  name: string;
  /** What role the tool plays in the pipeline. */
  kind: "collector" | "intake" | "parser-lib" | "canonicalizer" | "detection" | "analysis-runner" | "enrichment" | "agent" | "report" | "domain-analyzer" | "platform";
  /** SemVer of the tool. */
  version: string;
  /** Source repo slug. */
  repository?: string;
  consumes?: {
    content_types?: string[];
    filenames?: string[];
    /** Contract $ids consumed. */
    schema?: string[];
  };
  produces?: {
    /** Contract $ids produced. */
    schema?: string[];
    artifact_types?: string[];
  };
  /** Other suite tools or substrate (elasticsearch, redis, minio) this tool needs. */
  dependencies?: string[];
  /** How to probe liveness (HTTP endpoint for services, CLI for tools). */
  health?: {
    endpoint?: string;
    command?: string;
  };
  status?: "built" | "partial" | "planned";
}
