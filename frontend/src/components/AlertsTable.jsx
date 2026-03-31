const severityCls = {
  critical: 'text-danger',
  high: 'text-warn',
  medium: 'text-accent',
  low: 'text-success',
}

export default function AlertsTable({ alerts }) {
  return (
    <div className="bg-panel rounded-lg border border-slate-800 overflow-x-auto">
      <table className="min-w-full text-sm">
        <thead className="bg-panel2 text-muted">
          <tr>
            <th className="text-left p-3">Title</th>
            <th className="text-left p-3">Severity</th>
            <th className="text-left p-3">Status</th>
            <th className="text-left p-3">Created</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} className="border-t border-slate-800">
              <td className="p-3">{alert.title}</td>
              <td className={`p-3 font-semibold ${severityCls[(alert.severity || '').toLowerCase()] || ''}`}>{alert.severity}</td>
              <td className="p-3">{alert.status}</td>
              <td className="p-3">{alert.created_at}</td>
            </tr>
          ))}
          {alerts.length === 0 && (
            <tr>
              <td className="p-3 text-muted" colSpan={4}>No alerts found.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
