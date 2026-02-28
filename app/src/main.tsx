import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

import Admin from './Admin.tsx'

const isApp = window.location.pathname !== '/admin';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {isApp ? <App /> : <Admin />}
  </StrictMode>,
)
