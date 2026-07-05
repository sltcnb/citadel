// Shared case-level constants — imported by CaseTimeline and the extracted
// case panels so there is exactly one copy of each mapping.

export const MODULE_NAMES = {
  wintriage:   'Windows Triage',
  hayabusa:    'Hayabusa',
  hindsight:   'Hindsight',
  strings:     'Strings',
  regripper:   'RegRipper',
  chainsaw:    'Chainsaw',
  evtxecmd:    'EvtxECmd',
  volatility3: 'Volatility 3',
  yara:        'YARA Scanner',
  exiftool:    'ExifTool',
  bulk_extractor: 'Bulk Extractor',
  capa:        'CAPA',
}

// Finding `kind` → human label. Findings are the unified output of EVERY case
// feature (not just modules), so the report draws on all of them.
export const FINDING_KIND_LABELS = {
  module:       'Modules',
  ioc:          'IOCs',
  anomaly:      'Anomalies',
  mitre:        'MITRE',
  baseline:     'Baseline',
  killchain:    'Kill chain',
  entity:       'Entity graph',
  process_tree: 'Process tree',
  copilot:      'Co-Pilot',
  manual:       'Manual',
}

export function currentUser() {
  try { return JSON.parse(localStorage.getItem('fo_user')) } catch { return null }
}
