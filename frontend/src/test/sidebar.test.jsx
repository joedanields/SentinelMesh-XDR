import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import Sidebar from '../components/Sidebar'

test('renders sentinelmesh sidebar links', () => {
  render(
    <MemoryRouter>
      <Sidebar />
    </MemoryRouter>,
  )

  expect(screen.getByText('SentinelMesh XDR')).toBeInTheDocument()
  expect(screen.getByText('Overview')).toBeInTheDocument()
  expect(screen.getByText('AI Insights')).toBeInTheDocument()
})
