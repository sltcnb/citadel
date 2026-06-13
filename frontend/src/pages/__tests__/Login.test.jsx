import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

// Mock react-router so the component can render without a Router provider.
vi.mock('react-router-dom', () => ({
  useNavigate: () => vi.fn(),
  useLocation: () => ({ state: null, pathname: '/login' }),
}))

import Login from '../Login.jsx'

describe('Login form (credentials step)', () => {
  it('renders username, password fields and a Sign in button', () => {
    render(<Login onLogin={vi.fn()} />)

    // Query by placeholder — resilient to label/markup changes.
    expect(screen.getByPlaceholderText(/enter your username/i)).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/enter your password/i)).toBeInTheDocument()

    // Sign in submit button (there is a "Sign in" heading too, so scope to button role).
    const signInButton = screen.getByRole('button', { name: /sign in/i })
    expect(signInButton).toBeInTheDocument()
  })

  it('renders the Sign in heading', () => {
    render(<Login onLogin={vi.fn()} />)
    expect(screen.getByRole('heading', { name: /sign in/i })).toBeInTheDocument()
  })
})
