import { Loader2 } from 'lucide-react'

export default function RouteFallback() {
  return (
    <div className="flex-1 flex items-center justify-center text-gray-500 min-h-[50vh]">
      <Loader2 size={20} className="animate-spin mr-2" /> Loading…
    </div>
  )
}
