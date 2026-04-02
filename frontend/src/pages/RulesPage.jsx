import { useEffect, useMemo, useState } from 'react'
import { useAppStore } from '../store/useAppStore'

export default function RulesPage() {
  const [rule, setRule] = useState({
    id: '',
    name: '',
    type: 'pattern',
    severity: 'medium',
    priority: 50,
    condition: '{"field":"message","pattern":"failed password"}',
    description: '',
    mitre_technique: '',
    enabled: true,
  })
  const [message, setMessage] = useState('')

  const { rules, fetchRules, createRule, setRuleEnabled, deleteRule, loading, error } = useAppStore()

  useEffect(() => {
    fetchRules().catch(() => undefined)
  }, [fetchRules])

  const sortedRules = useMemo(
    () => [...rules].sort((a, b) => (b.priority || 0) - (a.priority || 0)),
    [rules],
  )

  const saveRule = async () => {
    try {
      const parsedCondition = JSON.parse(rule.condition)
      if (!rule.id || !rule.name) {
        setMessage('Rule id and name are required.')
        return
      }
      await createRule({
        id: rule.id,
        name: rule.name,
        type: rule.type,
        severity: rule.severity,
        priority: Number(rule.priority),
        condition: parsedCondition,
        description: rule.description,
        mitre_technique: rule.mitre_technique,
        enabled: rule.enabled,
      })
      setMessage('Rule created successfully.')
      setRule({
        id: '',
        name: '',
        type: 'pattern',
        severity: 'medium',
        priority: 50,
        condition: '{"field":"message","pattern":"failed password"}',
        description: '',
        mitre_technique: '',
        enabled: true,
      })
    } catch (e) {
      if (e instanceof SyntaxError) setMessage('Condition must be valid JSON.')
      else setMessage('Failed to create rule. Please verify rule fields and condition JSON.')
    }
  }

  const toggleRule = async (r) => {
    await setRuleEnabled(r.id, !r.enabled)
  }

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Rule Editor</h2>

      <div className="bg-panel border border-slate-800 rounded p-4 space-y-3 max-w-3xl">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <input
            placeholder="Rule ID (e.g. CUSTOM-001)"
            className="w-full bg-panel2 border border-slate-700 rounded px-3 py-2"
            value={rule.id}
            onChange={(e) => setRule({ ...rule, id: e.target.value })}
          />
          <input
            placeholder="Rule name"
            className="w-full bg-panel2 border border-slate-700 rounded px-3 py-2"
            value={rule.name}
            onChange={(e) => setRule({ ...rule, name: e.target.value })}
          />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <select
            className="w-full bg-panel2 border border-slate-700 rounded px-3 py-2"
            value={rule.type}
            onChange={(e) => setRule({ ...rule, type: e.target.value })}
          >
            <option value="signature">signature</option>
            <option value="pattern">pattern</option>
            <option value="threshold">threshold</option>
            <option value="statistical">statistical</option>
          </select>
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
          <input
            type="number"
            min={1}
            max={100}
            className="w-full bg-panel2 border border-slate-700 rounded px-3 py-2"
            value={rule.priority}
            onChange={(e) => setRule({ ...rule, priority: e.target.value })}
          />
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={rule.enabled}
              onChange={(e) => setRule({ ...rule, enabled: e.target.checked })}
            />
            Enabled
          </label>
        </div>
        <input
          placeholder="MITRE technique (optional, e.g. T1110)"
          className="w-full bg-panel2 border border-slate-700 rounded px-3 py-2"
          value={rule.mitre_technique}
          onChange={(e) => setRule({ ...rule, mitre_technique: e.target.value })}
        />
        <input
          placeholder="Description"
          className="w-full bg-panel2 border border-slate-700 rounded px-3 py-2"
          value={rule.description}
          onChange={(e) => setRule({ ...rule, description: e.target.value })}
        />
        <textarea
          rows={8}
          className="w-full bg-panel2 border border-slate-700 rounded px-3 py-2 font-mono text-sm"
          value={rule.condition}
          onChange={(e) => setRule({ ...rule, condition: e.target.value })}
        />
        <button className="bg-accent text-slate-900 px-4 py-2 rounded font-semibold" onClick={saveRule} disabled={loading}>
          {loading ? 'Saving...' : 'Create Rule'}
        </button>
        {message && <p className="text-sm text-muted">{message}</p>}
        {error && <p className="text-sm text-danger">{error}</p>}
      </div>

      <div className="bg-panel border border-slate-800 rounded p-4">
        <h3 className="text-lg font-semibold mb-3">Existing Rules ({sortedRules.length})</h3>
        <div className="overflow-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="text-muted border-b border-slate-800">
                <th className="py-2">ID</th>
                <th>Name</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Priority</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sortedRules.map((r) => (
                <tr key={r.id} className="border-b border-slate-900">
                  <td className="py-2 font-mono">{r.id}</td>
                  <td>{r.name}</td>
                  <td>{r.type}</td>
                  <td>{r.severity}</td>
                  <td>{r.priority}</td>
                  <td>{r.enabled ? 'Enabled' : 'Disabled'}</td>
                  <td className="space-x-2">
                    <button
                      className="px-2 py-1 rounded bg-slate-700 hover:bg-slate-600"
                      onClick={() => toggleRule(r)}
                    >
                      {r.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button
                      className="px-2 py-1 rounded bg-red-700 hover:bg-red-600"
                      onClick={() => deleteRule(r.id)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
              {sortedRules.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-4 text-muted">No rules found.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
