import { useState, useEffect } from 'react';
import { supabase } from './lib/supabase';
import type { Session } from '@supabase/supabase-js';
import { Menu, X, ArrowRight, LogOut, ChevronLeft, Mail, Phone, Calendar } from 'lucide-react';
import './App.css';

export interface Inquiry {
    id: string;
    created_at: string;
    name: string;
    email: string;
    phone?: string;
    project: string;
}

export default function Admin() {
    const [session, setSession] = useState<Session | null>(null);
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(true);
    const [authError, setAuthError] = useState('');

    const [inquiries, setInquiries] = useState<Inquiry[]>([]);
    const [fetching, setFetching] = useState(false);

    const [menuOpen, setMenuOpen] = useState(false);

    const fetchInquiries = async () => {
        setFetching(true);
        const { data, error } = await supabase
            .from('inquiries')
            .select('*')
            .order('created_at', { ascending: false });

        if (error) {
            console.error('Error fetching inquiries:', error);
        } else {
            setInquiries(data || []);
        }
        setFetching(false);
    };

    useEffect(() => {
        supabase.auth.getSession().then(({ data: { session } }) => {
            setSession(session);
            setLoading(false);
            if (session) {
                fetchInquiries();
            }
        });

        const {
            data: { subscription },
        } = supabase.auth.onAuthStateChange((_event, session) => {
            setSession(session);
            if (session) {
                fetchInquiries();
            }
        });

        return () => subscription.unsubscribe();
    }, []);

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setAuthError('');
        const { error } = await supabase.auth.signInWithPassword({
            email,
            password,
        });
        if (error) setAuthError(error.message);
        setLoading(false);
    };

    const handleLogout = async () => {
        await supabase.auth.signOut();
    };

    const navigateHome = () => {
        window.location.href = '/';
    };

    return (
        <div className="app">
            {/* Fixed Navigation matching Main Page */}
            <nav className="navbar scrolled">
                <div className="nav-container">
                    <button className="logo" onClick={navigateHome}>
                        MACE REVAMP EB LTD
                    </button>

                    {/* Desktop Nav */}
                    <div className="nav-links desktop">
                        {session && (
                            <button className="nav-link" onClick={handleLogout}>
                                Logout
                            </button>
                        )}
                        <button onClick={navigateHome} className="nav-link">
                            Back to Site
                        </button>
                    </div>

                    {/* Mobile Menu Button */}
                    <button
                        className="menu-btn"
                        onClick={() => setMenuOpen(!menuOpen)}
                        aria-label="Toggle menu"
                    >
                        {menuOpen ? <X size={24} /> : <Menu size={24} />}
                    </button>
                </div>
            </nav>

            {/* Mobile Menu Overlay */}
            <div className={`mobile-menu ${menuOpen ? 'open' : ''}`}>
                <div className="mobile-menu-content">
                    {session && (
                        <button
                            onClick={() => {
                                handleLogout();
                                setMenuOpen(false);
                            }}
                            className="mobile-nav-link"
                        >
                            Logout
                        </button>
                    )}
                    <button onClick={navigateHome} className="mobile-nav-link">
                        Back to Site
                    </button>
                </div>
            </div>

            {/* Main Content Area */}
            <main style={{ minHeight: '100vh', paddingTop: '80px' }}>

                {loading ? (
                    <div className="container" style={{ textAlign: 'center', marginTop: '100px' }}>
                        <p>Loading Secure Panel...</p>
                    </div>
                ) : !session ? (

                    /* Login Design (Matches Contact Form Style) */
                    <section className="contact" style={{ padding: '80px 0', minHeight: 'calc(100vh - 80px)' }}>
                        <div className="container">
                            <div className="section-header" style={{ marginBottom: '2rem' }}>
                                <p className="section-label">Secure Access</p>
                                <h2 className="section-title">Admin Login</h2>
                            </div>

                            <div className="contact-form-wrapper" style={{ maxWidth: '500px', margin: '0 auto', backgroundColor: '#fff' }}>
                                <form className="contact-form" onSubmit={handleLogin}>
                                    <div className="form-group">
                                        <label htmlFor="email">Email Address</label>
                                        <input
                                            type="email"
                                            id="email"
                                            value={email}
                                            onChange={(e) => setEmail(e.target.value)}
                                            placeholder="admin@example.com"
                                            required
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label htmlFor="password">Password</label>
                                        <input
                                            type="password"
                                            id="password"
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                            placeholder="••••••••"
                                            required
                                        />
                                    </div>

                                    {authError && (
                                        <div className="error-message" style={{ color: '#ef4444', marginBottom: '1rem', padding: '0.75rem', backgroundColor: '#fee2e2', borderRadius: '4px', border: '1px solid #f87171' }}>
                                            {authError}
                                        </div>
                                    )}

                                    <button type="submit" className="btn btn-primary btn-full" disabled={loading}>
                                        {loading ? 'Authenticating...' : (
                                            <>Login to Dashboard <ArrowRight size={18} /></>
                                        )}
                                    </button>
                                </form>
                            </div>
                        </div>
                    </section>

                ) : (

                    /* Dashboard Design */
                    <section className="services" style={{ padding: '80px 0', minHeight: 'calc(100vh - 80px)' }}>
                        <div className="container" style={{ maxWidth: '1200px' }}>
                            <div className="section-header" style={{ marginBottom: '3rem', textAlign: 'left', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                                <div>
                                    <p className="section-label">Overview</p>
                                    <h2 className="section-title" style={{ marginBottom: '0', color: 'var(--color-text)' }}>Inquiries Dashboard</h2>
                                </div>
                                <button onClick={handleLogout} className="btn btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                    <LogOut size={18} /> Logout
                                </button>
                            </div>

                            {fetching ? (
                                <div style={{ padding: '4rem', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                                    Loading inquiries...
                                </div>
                            ) : inquiries.length === 0 ? (
                                <div style={{ padding: '4rem', textAlign: 'center', color: 'var(--color-text-muted)', background: 'rgba(255,255,255,0.03)', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.08)' }}>
                                    <p style={{ fontSize: '1.25rem', marginBottom: '1rem', color: 'var(--color-text)' }}>No inquiries found.</p>
                                    <p>When leads submit the contact form, they will appear here.</p>
                                </div>
                            ) : (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
                                    {inquiries.map((inq) => (
                                        <div key={inq.id} className="service-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', height: '100%' }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px', marginBottom: '24px' }}>
                                                <div>
                                                    <h3 className="service-title" style={{ marginBottom: '12px', fontSize: '24px', color: 'var(--color-text)' }}>{inq.name}</h3>
                                                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px' }}>
                                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text-muted)', fontSize: '16px' }}>
                                                            <Mail size={16} className="service-icon" style={{ marginBottom: 0 }} />
                                                            <a href={`mailto:${inq.email}`} style={{ color: 'var(--color-text-muted)', textDecoration: 'none', transition: 'color 0.2s', wordBreak: 'break-all' }} onMouseEnter={e => e.currentTarget.style.color = 'var(--color-accent)'} onMouseLeave={e => e.currentTarget.style.color = 'var(--color-text-muted)'}>{inq.email}</a>
                                                        </div>
                                                        {inq.phone && (
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text-muted)', fontSize: '16px' }}>
                                                                <Phone size={16} className="service-icon" style={{ marginBottom: 0 }} /> {inq.phone}
                                                            </div>
                                                        )}
                                                    </div>
                                                </div>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-accent)', fontSize: '14px', background: 'rgba(198, 142, 78, 0.1)', padding: '8px 16px', borderRadius: '8px', fontWeight: '600' }}>
                                                    <Calendar size={14} /> {new Date(inq.created_at).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                                                </div>
                                            </div>

                                            <div style={{ marginTop: 'auto', paddingTop: '24px', borderTop: '1px solid rgba(255,255,255,0.1)' }}>
                                                <p style={{ fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--color-accent)', marginBottom: '16px', fontWeight: '600' }}>Project Details & Requirements</p>
                                                <div style={{ background: 'rgba(0,0,0,0.2)', padding: '24px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
                                                    <p className="service-description" style={{ fontSize: '17px', whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflowWrap: 'break-word', lineHeight: '1.8', color: 'var(--color-text)' }}>{inq.project}</p>
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </section>
                )}
            </main>

            {/* Footer matching Main Page */}
            <footer className="footer">
                <div className="container">
                    <div className="footer-content" style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
                        <div className="footer-brand" style={{ textAlign: 'center' }}>
                            <h3>MACE REVAMP EB LTD</h3>
                            <p style={{ maxWidth: '400px', margin: '0 auto' }}>Premium carpentry and joinery services across London and the UK.</p>
                        </div>
                        <div style={{ textAlign: 'center', marginTop: '1rem' }}>
                            <button onClick={navigateHome} className="btn btn-secondary" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
                                <ChevronLeft size={16} /> Back to Public Site
                            </button>
                        </div>
                    </div>
                    <div className="footer-bottom" style={{ marginTop: '3rem' }}>
                        <p>© {new Date().getFullYear()} MACE REVAMP EB LTD. All rights reserved.</p>
                    </div>
                </div>
            </footer>
        </div>
    );
}
