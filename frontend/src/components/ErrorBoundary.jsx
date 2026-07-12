import { Component } from 'react'

/**
 * App-wide error boundary. Catches render-time errors (including failed lazy
 * chunk fetches after a deploy invalidates hashed filenames) so the user gets
 * a recovery action instead of a blank white screen.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    console.error('Unhandled UI error:', error, info)
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children

    // A failed dynamic import (stale chunk after a new deploy) is best resolved
    // by a hard reload, which re-fetches the current asset manifest.
    const isChunkError = /Loading chunk|dynamically imported module|Failed to fetch/i.test(
      error?.message || '',
    )

    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-950 text-gray-100 p-6">
        <div className="max-w-md text-center space-y-4">
          <h1 className="text-lg font-semibold">Something went wrong</h1>
          <p className="text-sm text-gray-400">
            {isChunkError
              ? 'The app was updated. Reload to get the latest version.'
              : 'An unexpected error occurred while rendering this page.'}
          </p>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium"
          >
            Reload
          </button>
        </div>
      </div>
    )
  }
}
