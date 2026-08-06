import { Link } from 'react-router'
import { Boxes } from 'lucide-react'

/* ── Tool byline ──────────────────────────────────────────────────────────
 * Drop <ToolByline tool="babel" /> at the top of a feature page to mark which
 * suite tool powers it, with a link back to the Suite overview. Lives in its
 * own module (not pages/Suite) so importing it from the layout doesn't pull
 * the whole lazy-loaded Suite page into the eager chunk.
 */
export function ToolByline({ tool, className = '' }) {
  if (!tool) return null
  // Derive from the key — no static registry. (Bylines are tiny labels; the
  // rich per-tool data lives in the manifest, shown on the Suite page.)
  const name = tool.charAt(0).toUpperCase() + tool.slice(1)
  return (
    <Link
      to="/suite"
      title={`${name} — see the full suite`}
      className={`inline-flex items-center gap-1.5 text-[11px] text-gray-500 hover:text-brand-accent border border-gray-200 hover:border-brand-accent rounded-full pl-1.5 pr-2 py-0.5 ${className}`}
    >
      <Boxes size={11} className="text-brand-accent" />
      <span>Powered by <span className="font-semibold">{name}</span></span>
    </Link>
  )
}
