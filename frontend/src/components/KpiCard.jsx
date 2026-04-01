export default function KpiCard({ title, value, subtitle }) {
  return (
    <div className="bg-panel rounded-lg p-4 border border-slate-800">
      <p className="text-sm text-muted">{title}</p>
      <h3 className="text-2xl font-bold mt-1">{value}</h3>
      <p className="text-xs text-muted mt-1">{subtitle}</p>
    </div>
  )
}
