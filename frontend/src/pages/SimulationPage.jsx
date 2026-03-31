import { useState } from 'react'
import { useAppStore } from '../store/useAppStore'

export default function SimulationPage() {
  const [scenario, setScenario] = useState('brute_force')
  const [result, setResult] = useState(null)
  const { runSimulation, loading, error } = useAppStore()

  const onRun = async () => {
    const data = await runSimulation(scenario)
    setResult(data)
  }

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Simulation Panel</h2>
      <div className="flex gap-3">
        <select
          value={scenario}
          onChange={(e) => setScenario(e.target.value)}
          className="bg-panel border border-slate-700 rounded px-3 py-2"
        >
          <option value="brute_force">Brute Force</option>
          <option value="sql_injection">SQL Injection</option>
          <option value="port_scan">Port Scan</option>
          <option value="lateral_movement">Lateral Movement</option>
          <option value="data_exfiltration">Data Exfiltration</option>
          <option value="full_apt_chain">Full APT Chain</option>
        </select>
        <button className="bg-accent text-slate-900 px-4 py-2 rounded font-semibold" onClick={onRun} disabled={loading}>
          {loading ? 'Running...' : 'Run Simulation'}
        </button>
      </div>
      {error && <p className="text-danger">{error}</p>}
      {result && (
        <div className="bg-panel border border-slate-800 rounded p-4">
          <p>Scenario: <strong>{result.scenario}</strong></p>
          <p>Generated events: <strong>{result.generated_events}</strong></p>
        </div>
      )}
    </div>
  )
}
