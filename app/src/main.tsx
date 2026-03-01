import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import Admin from './Admin.tsx'
import Inquiries from './Inquiries.tsx'
import NotFound from './NotFound.tsx'
import ErrorBoundary from './ErrorBoundary.tsx'

const path = window.location.pathname;

function Root() {
  if (path === '/manage-8x7k') return <Admin />;
  if (path === '/inquiries' || path === '/inquery') return <Inquiries />;
  if (path === '/') return <App />;
  return <NotFound />;
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <Root />
    </ErrorBoundary>
  </StrictMode>,
)
