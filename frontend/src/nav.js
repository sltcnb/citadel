// Single source of truth for navigation.
//
// The top-nav dropdowns, the mobile drawer, the ⌘K command palette and the
// keyboard-shortcuts modal are ALL derived from the definitions here — so a
// label or route only ever needs changing in one place and the surfaces can't
// drift apart (the audit found "Malware" vs "Malware Analysis" and a palette
// missing Stack / Templates / Logs / Account).
import {
  LayoutDashboard, FolderOpen, Bell, FileCode, Shield, FlaskConical,
  Cpu, Code2, PackageOpen, Puzzle, BookOpen, Activity, Users, Settings2,
  UserCircle, Search, ListChecks, ScrollText, Boxes, LayoutTemplate,
} from 'lucide-react'

// Home / dashboard — rendered as a standalone top-nav link (not in a dropdown).
export const HOME_ITEM = { to: '/', icon: LayoutDashboard, label: 'Dashboard', end: true }

// Account — reachable from the avatar / mobile drawer; also exposed in ⌘K.
export const ACCOUNT_ITEM = { to: '/account', icon: UserCircle, label: 'Account' }

// Grouped navigation used by the top-nav dropdowns and the mobile drawer.
export const NAV_GROUPS = [
  {
    label: 'Analyze',
    items: [
      { to: '/cross-search', icon: Search,       label: 'Cross-Case Search' },
      { to: '/malware',      icon: FlaskConical,  label: 'Malware Analysis'  },
      { to: '/modules',      icon: Cpu,           label: 'Modules'           },
      { to: '/collector',    icon: PackageOpen,   label: 'Collector'         },
    ],
  },
  {
    label: 'Knowledge',
    items: [
      { to: '/alert-rules', icon: Bell,           label: 'Alert Rules'   },
      { to: '/yara-rules',  icon: FileCode,       label: 'YARA Rules'    },
      { to: '/templates',   icon: LayoutTemplate, label: 'Templates'     },
      { to: '/cti',         icon: Shield,         label: 'Threat Intel'  },
      { to: '/watchlist',   icon: ListChecks,     label: 'IOC Watchlist' },
    ],
  },
  {
    label: 'Platform',
    adminOnly: true,
    items: [
      { to: '/suite',     icon: Boxes,   label: 'Stack'     },
      { to: '/studio',    icon: Code2,   label: 'Studio'    },
      { to: '/ingesters', icon: Puzzle,  label: 'Ingesters' },
      { to: '/docs',      icon: BookOpen, label: 'Docs'     },
    ],
  },
  {
    label: 'Admin',
    adminOnly: true,
    items: [
      { to: '/settings',    icon: Settings2,  label: 'Platform Settings' },
      { to: '/performance', icon: Activity,   label: 'Performance'       },
      { to: '/logs',        icon: ScrollText, label: 'Tool Logs'         },
      { to: '/users',       icon: Users,      label: 'Users'             },
    ],
  },
]

// Flat list of every navigable destination, in a sensible order — the source
// for the ⌘K command palette so it can never fall behind the top-nav.
export const NAV_ITEMS = [
  HOME_ITEM,
  ...NAV_GROUPS.flatMap(g => g.items),
  ACCOUNT_ITEM,
]

// Keyboard shortcuts. `keys` drives the modal display AND the actual binding in
// the layout (via useKeyboardShortcuts), so the help never lies about a key.
export const NAV_SHORTCUTS = [
  { keys: ['g', 'd'], label: 'Dashboard',   to: '/'            },
  { keys: ['g', 'c'], label: 'Cases',       to: '/cases'       },
  { keys: ['g', 'a'], label: 'Alert Rules', to: '/alert-rules' },
  { keys: ['g', 't'], label: 'Threat Intel', to: '/cti'        },
  { keys: ['g', 'm'], label: 'Modules',     to: '/modules'     },
  { keys: ['g', 's'], label: 'Studio',      to: '/studio'      },
]

// Non-navigation shortcuts (new case, help, close) shown in the modal.
export const GLOBAL_SHORTCUTS = [
  { keys: ['g', 'n'], label: 'New case'        },
  { keys: ['?'],      label: 'Show this help'  },
  { keys: ['Esc'],    label: 'Close this panel' },
]

// Icon used for dynamic case-jump entries in the palette.
export const CASE_ICON = FolderOpen
