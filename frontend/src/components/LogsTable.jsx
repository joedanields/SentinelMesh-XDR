export default function LogsTable({ logs }) {
  return (
    <div className="bg-panel rounded-lg border border-slate-800 overflow-x-auto">
      <table className="min-w-full text-sm">
        <thead className="bg-panel2 text-muted">
          <tr>
            <th className="text-left p-3">Timestamp</th>
            <th className="text-left p-3">Source</th>
            <th className="text-left p-3">Severity</th>
            <th className="text-left p-3">Event</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log) => (
            <tr key={log.id || `${log.timestamp}-${log.source}`} className="border-t border-slate-800">
              <td className="p-3">{log.timestamp}</td>
              <td className="p-3">{log.source}</td>
              <td className="p-3">{log.severity}</td>
              <td className="p-3">{log.event_type || '-'}</td>
            </tr>
          ))}
          {logs.length === 0 && (
            <tr>
              <td className="p-3 text-muted" colSpan={4}>No logs available.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
