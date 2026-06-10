export function computeServiceLevels(metrics) {
  return {
    elasticsearch: !metrics?.elasticsearch ? 'red'
      : metrics.elasticsearch.status === 'green' ? 'green'
      : metrics.elasticsearch.status === 'yellow' ? 'yellow' : 'red',
    redis:   metrics?.redis?.connected_clients  != null ? 'green' : 'red',
    minio:   metrics?.minio?.bucket_count       != null ? 'green' : 'red',
    workers: !metrics?.celery ? 'red'
      : (metrics.celery.active_tasks > 0 && metrics.celery.registered_workers === 0) ? 'yellow'
      : 'green',
    api: (metrics?.api?.error_rate_pct || 0) > 5 ? 'yellow' : 'green',
  }
}

export function statusColor(level) {
  if (level === 'green')  return { dot: 'bg-green-500',  text: 'text-green-700',  sub: 'text-green-600',  bg: 'bg-green-100',  border: 'border-green-200' }
  if (level === 'yellow') return { dot: 'bg-amber-500',  text: 'text-amber-700',  sub: 'text-amber-600',  bg: 'bg-amber-100',  border: 'border-amber-200' }
  return                         { dot: 'bg-red-500',    text: 'text-red-700',    sub: 'text-red-600',    bg: 'bg-red-100',    border: 'border-red-200'   }
}

export function overallLevel(services) {
  if (!services || services.length === 0) return 'green'
  if (services.every(s => s.level === 'green')) return 'green'
  if (services.some(s  => s.level === 'red'))   return 'red'
  return 'yellow'
}
