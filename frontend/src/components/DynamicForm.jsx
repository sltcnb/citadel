import { useMemo } from 'react'

/*
 * Renders a form from a tool's declared input-field spec (see
 * citadel_contracts.capabilities). One component handles every tool — the tool
 * defines the fields, Citadel renders the controls. Adding a field type is the
 * only change needed here and in the contract's FIELD_TYPES.
 *
 * Props:
 *   fields   — array of {name,type,label,required,default,options,help,placeholder,depends_on,min,max}
 *   values   — current values object
 *   onChange — (next values) => void
 */

export function defaultsFor(fields = []) {
  const v = {}
  for (const f of fields) {
    if (f.default !== undefined && f.default !== null) v[f.name] = f.default
    else if (f.type === 'multiselect') v[f.name] = []
    else if (f.type === 'bool') v[f.name] = false
    else v[f.name] = ''
  }
  return v
}

// Which fields are missing a required value (for submit-gating).
export function missingRequired(fields = [], values = {}) {
  return fields
    .filter(f => visible(f, values) && f.required)
    .filter(f => {
      const v = values[f.name]
      if (f.type === 'multiselect') return !Array.isArray(v) || v.length === 0
      if (f.type === 'bool') return false
      return v === undefined || v === null || v === ''
    })
    .map(f => f.label || f.name)
}

function visible(f, values) {
  if (!f.depends_on) return true
  return values[f.depends_on.field] === f.depends_on.equals
}

export default function DynamicForm({ fields = [], values = {}, onChange }) {
  const set = (name, val) => onChange({ ...values, [name]: val })
  const shown = useMemo(() => fields.filter(f => visible(f, values)), [fields, values])

  if (!fields.length) {
    return <p className="text-xs text-gray-400 italic">No inputs — runs automatically.</p>
  }

  return (
    <div className="space-y-3">
      {shown.map(f => (
        <div key={f.name}>
          {f.type !== 'bool' && (
            <label className="block text-xs font-medium text-gray-600 mb-1">
              {f.label || f.name}
              {f.required && <span className="text-red-500 ml-0.5">*</span>}
            </label>
          )}
          <Field f={f} value={values[f.name]} set={v => set(f.name, v)} />
          {f.help && <p className="text-[10px] text-gray-400 mt-1">{f.help}</p>}
        </div>
      ))}
    </div>
  )
}

function Field({ f, value, set }) {
  const base = 'input text-sm w-full'
  switch (f.type) {
    case 'bool':
      return (
        <label className="flex items-center gap-2 text-xs text-gray-700 cursor-pointer select-none">
          <input type="checkbox" checked={!!value}
            onChange={e => set(e.target.checked)}
            className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent" />
          {f.label || f.name}
        </label>
      )
    case 'text':
      return <textarea className={base} rows={3} placeholder={f.placeholder}
        value={value ?? ''} onChange={e => set(e.target.value)} />
    case 'int':
    case 'float':
      return <input type="number" className={base} placeholder={f.placeholder}
        min={f.min} max={f.max} step={f.type === 'int' ? 1 : 'any'}
        value={value ?? ''} onChange={e => set(e.target.value === '' ? '' : Number(e.target.value))} />
    case 'secret':
      return <input type="password" className={base} placeholder={f.placeholder}
        value={value ?? ''} onChange={e => set(e.target.value)} />
    case 'enum':
      return (
        <select className={base} value={value ?? ''} onChange={e => set(e.target.value)}>
          {!f.required && <option value="">—</option>}
          {f.options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      )
    case 'multiselect':
      return <MultiSelect options={f.options} value={Array.isArray(value) ? value : []} set={set} />
    default: // string, path, host
      return <input type="text" className={base} placeholder={f.placeholder}
        value={value ?? ''} onChange={e => set(e.target.value)} />
  }
}

function MultiSelect({ options, value, set }) {
  const toggle = v => set(value.includes(v) ? value.filter(x => x !== v) : [...value, v])
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
      {options.map(o => {
        const on = value.includes(o.value)
        return (
          <button
            type="button"
            key={o.value}
            onClick={() => toggle(o.value)}
            title={o.desc || ''}
            className={`text-left text-xs rounded-lg border px-2.5 py-1.5 transition-colors ${
              on ? 'border-brand-accent bg-brand-accentlight text-brand-text'
                 : 'border-gray-200 text-gray-600 hover:border-gray-300'
            }`}
          >
            <span className="flex items-center gap-1.5">
              <span className={`w-3 h-3 rounded-sm border flex-shrink-0 ${on ? 'bg-brand-accent border-brand-accent' : 'border-gray-300'}`} />
              <span className="font-medium">{o.label}</span>
            </span>
            {o.desc && <span className="block text-[10px] text-gray-400 mt-0.5 ml-[18px] leading-tight">{o.desc}</span>}
          </button>
        )
      })}
    </div>
  )
}
