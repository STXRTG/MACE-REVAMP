import './App.css';

export default function NotFound() {
    return (
        <div className="app">
            <div style={{
                minHeight: '100vh',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                background: 'var(--color-bg)',
                color: 'var(--color-text)',
                textAlign: 'center',
                padding: '24px',
            }}>
                <p style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: '13px',
                    fontWeight: 500,
                    letterSpacing: '0.15em',
                    textTransform: 'uppercase' as const,
                    color: 'var(--color-accent)',
                    marginBottom: '12px',
                }}>
                    Error 404
                </p>
                <h1 style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: 'clamp(32px, 5vw, 48px)',
                    fontWeight: 700,
                    marginBottom: '16px',
                }}>
                    Page Not Found
                </h1>
                <p style={{
                    fontSize: '17px',
                    color: 'var(--color-text-muted)',
                    marginBottom: '32px',
                    maxWidth: '480px',
                }}>
                    The page you're looking for doesn't exist or has been moved.
                </p>
                <button
                    onClick={() => { window.location.href = '/'; }}
                    className="btn btn-primary"
                >
                    Back to Home
                </button>
            </div>
        </div>
    );
}
