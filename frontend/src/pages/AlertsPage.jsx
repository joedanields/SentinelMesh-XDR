import { useEffect, useState } from 'react'
import AlertsTable from '../components/AlertsTable'
import { useAppStore } from '../store/useAppStore'

export default function AlertsPage() {
  const [severity, setSeverity] = useState('')
  const { alerts, fetchAlerts, loading, error } = useAppStore()

  useEffect(() => {
    fetchAlerts(severity)
  }, [fetchAlerts, severity])

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Alerts Panel</h2>
      <div>
        <label className="text-sm text-muted mr-2">Severity</label>
        <select
          className="bg-panel border border-slate-700 rounded px-2 py-1"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          <option value="">All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>
      {loading && <p className="text-muted">Loading alerts...</p>}
      {error && <p className="text-danger">{error}</p>}
      <AlertsTable alerts={alerts} />
    </div>
  )
}
