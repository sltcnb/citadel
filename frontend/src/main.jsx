import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import { installGlobalErrorReporting } from './lib/telemetry'

// Installed before React mounts so errors thrown during the very first render
// — or outside the component tree entirely — are still reported.
installGlobalErrorReporting()

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
