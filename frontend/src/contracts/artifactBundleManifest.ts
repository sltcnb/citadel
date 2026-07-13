// AUTO-GENERATED from contracts/bundle_manifest.schema.json -- do not edit by hand.
// Regenerate: scripts/contracts_codegen.py
// Contract: https://citadel.dfir/contracts/bundle_manifest/v1.json

/** ArtifactBundleManifest */
export interface ArtifactBundleManifest {
  session_id: string;
  hostname: string;
  os: "windows" | "linux" | "macos" | "cloud" | "unknown";
  started_at: string;
  finished_at?: string;
  artifacts: {
    name: string;
    sha256: string;
    size: number;
    category: string;
  }[];
  artifact_count: number;
  total_bytes?: number;
  errors?: string[];
  [key: string]: unknown;
}
