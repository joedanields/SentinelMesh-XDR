import { useState } from 'react'

export default function RulesPage() {
  const [rule, setRule] = useState({ name: '', severity: 'medium', condition: '{}' })
  const [message, setMessage] = useState('')

  const saveRule = () => {
    try {
      JSON.parse(rule.condition)
      setMessage('Rule validated locally. Connect to /rules API to persist.')
    } catch {
      setMessage('Condition must be valid JSON.')
    }
  }

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Rule Editor</h2>
      <div className="bg-panel border border-slate-800 rounded p-4 space-y-3 max-w-2xl">
        <input
          placeholder="Rule name"
          className="w-full bg-panel2 border border-slate-700 rounded px-3 py-2"
          value={rule.name}
          onChange={(e) => setRule({ ...rule, name: e.target.value })}
        />
        <select
          className="w-full bg-panel2 border border-slate-700 rounded px-3 py-2"
          value={rule.severity}
          onChange={(e) => setRule({ ...rule, severity: e.target.value })}
        >
          <option>low</option>
          <option>medium</option>
          <option>high</option>
          <option>critical</option>
        </select>
        <textarea
          rows={8}
          className="w-full bg-panel2 border border-slate-700 rounded px-3 py-2 font-mono text-sm"
          value={rule.condition}
          onChange={(e) => setRule({ ...rule, condition: e.target.value })}
        />
        <button className="bg-accent text-slate-900 px-4 py-2 rounded font-semibold" onClick={saveRule}>Validate Rule</button>
        {message && <p className="text-sm text-muted">{message}</p>}
      </div>
    </div>
  )
}
