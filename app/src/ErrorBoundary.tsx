import { Component, type ReactNode } from 'react';

interface Props {
    children: ReactNode;
}

interface State {
    hasError: boolean;
}

export default class ErrorBoundary extends Component<Props, State> {
    constructor(props: Props) {
        super(props);
        this.state = { hasError: false };
    }

    static getDerivedStateFromError(): State {
        return { hasError: true };
    }

    componentDidCatch() { }

    render() {
        if (this.state.hasError) {
            return (
                <div style={{
                    minHeight: '100vh',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    background: '#1A1A1A',
                    color: '#F3EFE7',
                    fontFamily: "'Space Grotesk', sans-serif",
                    textAlign: 'center',
                    padding: '24px',
                }}>
                    <h1 style={{ fontSize: '48px', fontWeight: 700, marginBottom: '16px' }}>
                        Something went wrong
                    </h1>
                    <p style={{ fontSize: '17px', color: 'rgba(243,239,231,0.7)', marginBottom: '32px', maxWidth: '480px' }}>
                        An unexpected error occurred. Please refresh the page to try again.
                    </p>
                    <button
                        onClick={() => window.location.reload()}
                        style={{
                            padding: '14px 28px',
                            background: '#C68E4E',
                            color: '#1A1A1A',
                            border: 'none',
                            borderRadius: '4px',
                            fontSize: '15px',
                            fontWeight: 600,
                            fontFamily: "'Space Grotesk', sans-serif",
                            cursor: 'pointer',
                        }}
                    >
                        Refresh Page
                    </button>
                </div>
            );
        }

        return this.props.children;
    }
}
