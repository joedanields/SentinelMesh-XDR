import { create } from 'zustand'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000/api/v1'

export const useAppStore = create((set, get) => ({
  logs: [],
  alerts: [],
  incidents: [],
  insights: null,
  loading: false,
  error: null,

  setError: (error) => set({ error }),
  clearError: () => set({ error: null }),

  async fetchLogs() {
    set({ loading: true, error: null })
    try {
      const res = await fetch(`${API_BASE}/logs`).catch(() => null)
      if (res && res.ok) {
        const data = await res.json()
        set({ logs: data.items || [] })
      }
    } catch (err) {
      set({ error: `Failed fetching logs: ${err.message}` })
    } finally {
      set({ loading: false })
    }
  },

  async fetchAlerts(severity = '') {
    set({ loading: true, error: null })
    try {
      const query = severity ? `?severity=${encodeURIComponent(severity)}` : ''
      const res = await fetch(`${API_BASE}/alerts${query}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      set({ alerts: data.items || [] })
    } catch (err) {
      set({ error: `Failed fetching alerts: ${err.message}` })
    } finally {
      set({ loading: false })
    }
  },

  async fetchIncidents() {
    set({ loading: true, error: null })
    try {
      const res = await fetch(`${API_BASE}/incidents`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      set({ incidents: data.items || [] })
    } catch (err) {
      set({ error: `Failed fetching incidents: ${err.message}` })
    } finally {
      set({ loading: false })
    }
  },

  async runSimulation(scenario) {
    set({ loading: true, error: null })
    try {
      const res = await fetch(`${API_BASE}/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return await res.json()
    } catch (err) {
      set({ error: `Simulation failed: ${err.message}` })
      throw err
    } finally {
      set({ loading: false })
    }
  },

  async runAgentAnalysis(payload) {
    set({ loading: true, error: null })
    try {
      const res = await fetch(`${API_BASE}/agents/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      set({ insights: data.report || null })
      return data
    } catch (err) {
      set({ error: `Agent analysis failed: ${err.message}` })
      throw err
    } finally {
      set({ loading: false })
    }
  },
}))

export const pollEvery = (fn, intervalMs = 5000) => {
  const id = setInterval(() => {
    Promise.resolve(fn()).catch(() => undefined)
  }, intervalMs)
  return () => clearInterval(id)
}
