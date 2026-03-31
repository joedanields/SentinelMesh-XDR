import { useEffect } from 'react'
import IncidentTimeline from '../components/IncidentTimeline'
import { useAppStore } from '../store/useAppStore'

export default function IncidentsPage() {
  const { incidents, fetchIncidents, loading, error } = useAppStore()

  useEffect(() => {
    fetchIncidents()
  }, [fetchIncidents])

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Incident Timeline</h2>
      {loading && <p className="text-muted">Loading incidents...</p>}
      {error && <p className="text-danger">{error}</p>}
      <IncidentTimeline incidents={incidents} />
    </div>
  )
}
