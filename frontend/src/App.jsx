import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import AlertsPage from './pages/AlertsPage'
import IncidentsPage from './pages/IncidentsPage'
import InsightsPage from './pages/InsightsPage'
import LogsPage from './pages/LogsPage'
import OverviewPage from './pages/OverviewPage'
import RulesPage from './pages/RulesPage'
import SimulationPage from './pages/SimulationPage'

function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/simulation" element={<SimulationPage />} />
          <Route path="/insights" element={<InsightsPage />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}

export default App
