import { useState, useEffect, useRef } from 'react';
import { supabase } from './lib/supabase';
import { Menu, X, ArrowRight } from 'lucide-react';
import './App.css';

type Session = { user: { id: string; email?: string } };

const NAV_ITEMS = [
    { id: 'home', label: 'Home' },
    { id: 'about', label: 'About' },
    { id: 'services', label: 'Services' },
    { id: 'work', label: 'Our Work' },
    { id: 'contact', label: 'Contact' },
];

const MIN_AUTH_DELAY = 1200;

function friendlyError(msg: string): string {
    const m = msg.toLowerCase();
    if (m.includes('invalid login') || m.includes('invalid credentials'))
        return 'Incorrect email or password. Please try again.';
    if (m.includes('email not confirmed'))
        return 'Your email has not been confirmed. Check your inbox.';
    if (m.includes('too many requests') || m.includes('rate'))
        return 'Too many attempts. Please wait a moment and try again.';
    if (m.includes('network') || m.includes('fetch'))
        return 'Unable to connect. Check your internet and try again.';
    if (m.includes('user not found'))
        return 'No account found with this email address.';
    if (m.includes('password'))
        return 'Incorrect password. Please try again.';
    return 'Something went wrong. Please try again later.';
}

function goTo(sectionId: string) {
    window.location.href = `/#${sectionId}`;
}

export default function Admin() {
    const [ready, setReady] = useState(false);
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const loadingRef = useRef(false);
    const [error, setError] = useState('');
    const [menuOpen, setMenuOpen] = useState(false);
    const [scrolled, setScrolled] = useState(false);

    useEffect(() => {
        const onScroll = () => setScrolled(window.scrollY > 50);
        window.addEventListener('scroll', onScroll, { passive: true });
        return () => window.removeEventListener('scroll', onScroll);
    }, []);

    useEffect(() => {
        const observer = new IntersectionObserver(
            (entries: IntersectionObserverEntry[]) => {
                entries.forEach((entry) => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('visible');
                    }
                });
            },
            { threshold: 0.1 }
        );

        const revealEls = document.querySelectorAll('.reveal');
        revealEls.forEach((el) => observer.observe(el));

        return () => {
            revealEls.forEach((el) => observer.unobserve(el));
        };
    }, [ready]);

    useEffect(() => {
        supabase.auth.getSession().then(({ data: { session: s } }: { data: { session: Session | null } }) => {
            if (s) {
                window.location.href = '/inquiries';
                return;
            }
            setReady(true);
        });

        const { data: { subscription } } = supabase.auth.onAuthStateChange((_event: string, s: Session | null) => {
            if (s && !loadingRef.current) {
                window.location.href = '/inquiries';
            }
        });

        return () => subscription.unsubscribe();
    }, []);

    const handleLogin = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setLoading(true);
        loadingRef.current = true;
        setError('');
        const t0 = Date.now();
        let fail: string | null = null;
        try {
            const { error: err } = await supabase.auth.signInWithPassword({ email, password });
            if (err) fail = friendlyError(err.message);
        } catch {
            fail = 'Unable to connect. Check your internet and try again.';
        }
        const delay = Math.max(0, MIN_AUTH_DELAY - (Date.now() - t0));
        setTimeout(() => {
            if (fail) {
                setError(fail);
                setLoading(false);
                loadingRef.current = false;
            } else {
                window.location.href = '/inquiries';
            }
        }, delay);
    };

    if (!ready) return <div className="app" style={{ minHeight: '100vh' }} />;

    return (
        <div className="app">
            <nav className={`navbar ${scrolled ? 'scrolled' : ''}`}>
                <div className="nav-container">
                    <button className="logo" onClick={() => goTo('home')}>MACE REVAMP EB LTD</button>
                    <div className="nav-links desktop">
                        {NAV_ITEMS.map(n => (
                            <button key={n.id} onClick={() => goTo(n.id)} className="nav-link">{n.label}</button>
                        ))}
                    </div>
                    <button className="menu-btn" onClick={() => setMenuOpen(!menuOpen)} aria-label="Toggle menu">
                        {menuOpen ? <X size={24} /> : <Menu size={24} />}
                    </button>
                </div>
            </nav>

            <div className={`mobile-menu ${menuOpen ? 'open' : ''}`}>
                <div className="mobile-menu-content">
                    {NAV_ITEMS.map(n => (
                        <button key={n.id} onClick={() => { goTo(n.id); setMenuOpen(false); }} className="mobile-nav-link">
                            {n.label}
                        </button>
                    ))}
                </div>
            </div>

            <section className="contact" id="login">
                <div className="container">
                    <div className="section-header reveal">
                        <p className="section-label">Secure Access</p>
                        <h2 className="section-title">Admin Login</h2>
                        <p className="section-subtitle">Sign in to manage inquiries and view submissions.</p>
                    </div>

                    <div style={{ maxWidth: '480px', margin: '0 auto' }} className="reveal reveal-delay-1">
                        <div className="contact-form-wrapper">
                            <form className="contact-form" onSubmit={handleLogin}>
                                <div className="form-group">
                                    <label htmlFor="login-email">Email Address</label>
                                    <input
                                        type="email" id="login-email" value={email}
                                        onChange={e => setEmail(e.target.value)}
                                        placeholder="admin@example.com"
                                        maxLength={255} autoComplete="email" required
                                    />
                                </div>

                                <div className="form-group">
                                    <label htmlFor="login-password">Password</label>
                                    <input
                                        type="password" id="login-password" value={password}
                                        onChange={e => setPassword(e.target.value)}
                                        placeholder="••••••••"
                                        maxLength={255} autoComplete="current-password" required
                                    />
                                </div>

                                {error && (
                                    <div role="alert" aria-live="assertive" style={{
                                        color: '#ef4444', margin: '0.75rem 0', padding: '0.75rem',
                                        backgroundColor: '#fee2e2', borderRadius: '4px',
                                        border: '1px solid #f87171', fontSize: '0.875rem',
                                    }}>
                                        {error}
                                    </div>
                                )}

                                <button type="submit" className="btn btn-primary btn-full" disabled={loading}>
                                    {loading ? 'Authenticating...' : <>Sign In <ArrowRight size={18} /></>}
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </section>

            <footer className="footer">
                <div className="container">
                    <div className="footer-content">
                        <div className="footer-brand">
                            <h3>MACE REVAMP EB LTD</h3>
                            <p>Premium carpentry and joinery services across London and the UK.</p>
                        </div>
                        <div className="footer-links">
                            <h4>Quick Links</h4>
                            <nav>
                                {NAV_ITEMS.map(n => (
                                    <button key={n.id} onClick={() => goTo(n.id)}>{n.label}</button>
                                ))}
                            </nav>
                        </div>
                        <div className="footer-contact">
                            <h4>Contact</h4>
                            <p>hello@macerevamp.co.uk</p>
                            <p>+44 (0)20 7946 0958</p>
                            <p>Mon–Fri, 8am–6pm</p>
                        </div>
                    </div>
                    <div className="footer-bottom">
                        <p>&copy; {new Date().getFullYear()} MACE REVAMP EB LTD. All rights reserved.</p>
                    </div>
                </div>
            </footer>
        </div>
    );
}
