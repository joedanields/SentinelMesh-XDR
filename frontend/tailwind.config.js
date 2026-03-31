/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#0b1020',
        panel: '#131a2f',
        panel2: '#1a2340',
        text: '#e2e8f0',
        muted: '#94a3b8',
        accent: '#22d3ee',
        danger: '#f43f5e',
        warn: '#f59e0b',
        success: '#22c55e',
      },
    },
  },
  plugins: [],
}
