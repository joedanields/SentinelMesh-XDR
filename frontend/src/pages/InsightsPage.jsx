import { useState } from 'react'
import { useAppStore } from '../store/useAppStore'

export default function InsightsPage() {
  const [payload, setPayload] = useState('{"message":"Suspicious login pattern detected","severity":"high"}')
  const { insights, runAgentAnalysis, loading, error } = useAppStore()

  const analyze = async () => {
    const parsed = JSON.parse(payload)
    await runAgentAnalysis(parsed)
  }

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">AI Insights Panel</h2>
      <textarea
        rows={8}
        className="w-full max-w-3xl bg-panel border border-slate-700 rounded p-3 font-mono text-sm"
        value={payload}
        onChange={(e) => setPayload(e.target.value)}
      />
      <div>
        <button className="bg-accent text-slate-900 px-4 py-2 rounded font-semibold" onClick={analyze} disabled={loading}>
          {loading ? 'Analyzing...' : 'Run AI Analysis'}
        </button>
      </div>
      {error && <p className="text-danger">{error}</p>}
      {insights && (
        <pre className="bg-panel border border-slate-800 rounded p-3 text-xs overflow-auto max-w-5xl">
          {JSON.stringify(insights, null, 2)}
        </pre>
      )}
    </div>
  )
}
