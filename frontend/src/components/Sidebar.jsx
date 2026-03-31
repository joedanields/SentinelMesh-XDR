import { NavLink } from 'react-router-dom'

const items = [
  ['/', 'Overview'],
  ['/logs', 'Live Logs'],
  ['/alerts', 'Alerts'],
  ['/incidents', 'Incidents'],
  ['/rules', 'Rules'],
  ['/simulation', 'Simulation'],
  ['/insights', 'AI Insights'],
]

export default function Sidebar() {
  return (
    <aside className="w-64 bg-panel border-r border-slate-800 p-4 min-h-screen">
      <h1 className="text-xl font-bold text-accent mb-6">SentinelMesh XDR</h1>
      <nav className="space-y-2">
        {items.map(([to, label]) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `block px-3 py-2 rounded ${isActive ? 'bg-panel2 text-accent' : 'text-text hover:bg-panel2'}`
            }
          >
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}
