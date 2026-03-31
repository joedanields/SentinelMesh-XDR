import { useEffect } from 'react'
import KpiCard from '../components/KpiCard'
import ThreatChart from '../components/ThreatChart'
import { pollEvery, useAppStore } from '../store/useAppStore'

export default function OverviewPage() {
  const { alerts, incidents, fetchAlerts, fetchIncidents, loading, error } = useAppStore()

  useEffect(() => {
    fetchAlerts()
    fetchIncidents()
    const stop1 = pollEvery(fetchAlerts, 8000)
    const stop2 = pollEvery(fetchIncidents, 10000)
    return () => {
      stop1()
      stop2()
    }
  }, [fetchAlerts, fetchIncidents])

  const critical = alerts.filter((a) => (a.severity || '').toLowerCase() === 'critical').length
  const high = alerts.filter((a) => (a.severity || '').toLowerCase() === 'high').length

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">SOC Overview</h2>
      {loading && <p className="text-muted">Loading data...</p>}
      {error && <p className="text-danger">{error}</p>}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <KpiCard title="Critical Alerts" value={critical} subtitle="Immediate response required" />
        <KpiCard title="High Alerts" value={high} subtitle="Escalate to analysts" />
        <KpiCard title="Active Alerts" value={alerts.length} subtitle="Current queue size" />
        <KpiCard title="Open Incidents" value={incidents.length} subtitle="Lifecycle in progress" />
      </div>
      <ThreatChart alerts={alerts} />
    </div>
  )
}
