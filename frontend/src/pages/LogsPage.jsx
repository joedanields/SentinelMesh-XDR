import { useEffect } from 'react'
import LogsTable from '../components/LogsTable'
import { pollEvery, useAppStore } from '../store/useAppStore'

export default function LogsPage() {
  const { logs, loading, error, fetchLogs } = useAppStore()

  useEffect(() => {
    fetchLogs()
    const stop = pollEvery(fetchLogs, 4000)
    return stop
  }, [fetchLogs])

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Live Logs Viewer</h2>
      {loading && <p className="text-muted">Loading logs...</p>}
      {error && <p className="text-danger">{error}</p>}
      <LogsTable logs={logs} />
    </div>
  )
}
