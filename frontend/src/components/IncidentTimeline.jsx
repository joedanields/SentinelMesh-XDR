export default function IncidentTimeline({ incidents }) {
  return (
    <div className="space-y-4">
      {incidents.map((incident) => (
        <div key={incident.id} className="bg-panel border border-slate-800 rounded-lg p-4">
          <div className="flex justify-between">
            <h3 className="font-semibold">{incident.title}</h3>
            <span className="text-muted text-sm">{incident.status}</span>
          </div>
          <p className="text-sm text-muted mt-1">Severity: {incident.severity}</p>
          <p className="text-sm mt-2">{incident.description || 'No description'}</p>
        </div>
      ))}
      {incidents.length === 0 && <p className="text-muted">No incidents yet.</p>}
    </div>
  )
}
