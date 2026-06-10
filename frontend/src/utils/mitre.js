/**
 * MITRE ATT&CK mappings for Windows Event IDs.
 */

export const MITRE_MAP = {
  // Credential Access
  4625: { id: 'T1110',     name: 'Brute Force',                tactic: 'Credential Access' },
  4771: { id: 'T1110.001', name: 'Password Guessing',          tactic: 'Credential Access' },
  4776: { id: 'T1110.002', name: 'NTLM Auth',                  tactic: 'Credential Access' },
  4768: { id: 'T1558.003', name: 'AS-REP Roasting',            tactic: 'Credential Access' },
  4769: { id: 'T1558.003', name: 'Kerberoasting',              tactic: 'Credential Access' },

  // Lateral Movement & Valid Accounts
  4624: { id: 'T1078',     name: 'Valid Accounts',             tactic: 'Lateral Movement' },
  4648: { id: 'T1134',     name: 'Token Impersonation',        tactic: 'Privilege Escalation' },
  4778: { id: 'T1563.002', name: 'Remote Desktop Protocol',    tactic: 'Lateral Movement' },
  4779: { id: 'T1563.002', name: 'Remote Desktop Protocol',    tactic: 'Lateral Movement' },

  // Execution
  4688: { id: 'T1059',     name: 'Command & Scripting',        tactic: 'Execution' },

  // Persistence
  4720: { id: 'T1136',     name: 'Create Account',             tactic: 'Persistence' },
  4722: { id: 'T1098',     name: 'Account Manipulation',       tactic: 'Persistence' },
  4732: { id: 'T1098',     name: 'Add Member to Group',        tactic: 'Persistence' },
  4698: { id: 'T1053.005', name: 'Scheduled Task',             tactic: 'Persistence' },
  4702: { id: 'T1053.005', name: 'Modify Scheduled Task',      tactic: 'Persistence' },
  7045: { id: 'T1543.003', name: 'Create System Service',      tactic: 'Persistence' },
  7040: { id: 'T1543.003', name: 'Modify System Service',      tactic: 'Persistence' },

  // Defense Evasion
  1102: { id: 'T1070.001', name: 'Clear Event Logs',           tactic: 'Defense Evasion' },
  4657: { id: 'T1112',     name: 'Modify Registry',            tactic: 'Defense Evasion' },
  4946: { id: 'T1562.004', name: 'Disable Firewall Rule',      tactic: 'Defense Evasion' },
  4948: { id: 'T1562.004', name: 'Delete Firewall Rule',       tactic: 'Defense Evasion' },
  4660: { id: 'T1070.004', name: 'File Deletion',              tactic: 'Defense Evasion' },
  4756: { id: 'T1484',     name: 'Group Policy Modification',  tactic: 'Defense Evasion' },

  // Discovery
  4663: { id: 'T1083',     name: 'File & Directory Discovery', tactic: 'Discovery' },
  5156: { id: 'T1049',     name: 'System Network Connections', tactic: 'Discovery' },

  // Impact
  4726: { id: 'T1531',     name: 'Account Access Removal',     tactic: 'Impact' },
  4740: { id: 'T1531',     name: 'Account Lockout',            tactic: 'Impact' },
}

export const TACTIC_COLORS = {
  'Credential Access':   'bg-red-100 text-red-700 border-red-200',
  'Defense Evasion':     'bg-orange-100 text-orange-700 border-orange-200',
  'Lateral Movement':    'bg-amber-100 text-amber-700 border-amber-200',
  'Execution':           'bg-pink-100 text-pink-700 border-pink-200',
  'Persistence':         'bg-purple-100 text-purple-700 border-purple-200',
  'Discovery':           'bg-blue-100 text-blue-700 border-blue-200',
  'Privilege Escalation':'bg-brand-accentlight text-brand-accent border-brand-accent/20',
  'Impact':              'bg-gray-100 text-gray-600 border-gray-200',
}

export function getMitre(event) {
  if (event.mitre?.technique_id) return event.mitre
  const eventId = event.evtx?.event_id
  if (eventId && MITRE_MAP[eventId]) {
    const m = MITRE_MAP[eventId]
    return { technique_id: m.id, technique_name: m.name, tactic: m.tactic }
  }
  return null
}
