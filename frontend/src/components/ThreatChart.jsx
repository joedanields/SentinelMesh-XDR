import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

export default function ThreatChart({ alerts }) {
  const counts = alerts.reduce((acc, a) => {
    const key = (a.severity || 'unknown').toLowerCase()
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})

  const data = Object.entries(counts).map(([severity, count]) => ({ severity, count }))

  return (
    <div className="bg-panel rounded-lg p-4 border border-slate-800 h-72">
      <h3 className="font-semibold mb-3">Alert Severity Distribution</h3>
      <ResponsiveContainer width="100%" height="85%">
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis dataKey="severity" stroke="#94a3b8" />
          <YAxis stroke="#94a3b8" />
          <Tooltip />
          <Bar dataKey="count" fill="#22d3ee" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
