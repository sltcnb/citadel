// Shared run/file status styling. Scheme: text-X-700 bg-X-50 border-X-200.

export const STATUS_STYLES = {
  PENDING:   { cls: 'text-amber-700 bg-amber-50 border-amber-200', label: 'Pending' },
  RUNNING:   { cls: 'text-blue-700 bg-blue-50 border-blue-200',    label: 'Running' },
  UPLOADING: { cls: 'text-sky-700 bg-sky-50 border-sky-200',       label: 'Uploading' },
  COMPLETED: { cls: 'text-green-700 bg-green-50 border-green-200', label: 'Completed' },
  FAILED:    { cls: 'text-red-700 bg-red-50 border-red-200',       label: 'Failed' },
  CANCELLED: { cls: 'text-gray-500 bg-gray-50 border-gray-200',    label: 'Cancelled' },
  SKIPPED:   { cls: 'text-gray-500 bg-gray-50 border-gray-200',    label: 'Skipped' },
}

export function statusStyle(status) {
  return STATUS_STYLES[String(status || '').toUpperCase()] || STATUS_STYLES.PENDING
}
