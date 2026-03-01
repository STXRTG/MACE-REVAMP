import { useState, useEffect, useCallback } from 'react';
import { supabase } from './lib/supabase';
import { Menu, X, Mail, Phone, Calendar, LogOut, Search, Archive, Trash2, RotateCcw, Clock, User } from 'lucide-react';
import './App.css';

type Session = { user: { id: string; email?: string } };

type InquiryStatus = 'active' | 'archived' | 'deleted';
type FilterTab = InquiryStatus | 'all';

type Inquiry = {
    id: string;
    name: string;
    email: string;
    phone: string;
    project: string;
    status: InquiryStatus;
    created_at: string;
    deleted_at: string | null;
    archived_at: string | null;
};

const NAV_ITEMS = [
    { id: 'home', label: 'Home' },
    { id: 'about', label: 'About' },
    { id: 'services', label: 'Services' },
    { id: 'work', label: 'Our Work' },
    { id: 'contact', label: 'Contact' },
];

const FILTER_TABS: { key: FilterTab; label: string }[] = [
    { key: 'active', label: 'Active' },
    { key: 'archived', label: 'Archived' },
    { key: 'deleted', label: 'Deleted' },
    { key: 'all', label: 'All' },
];

function goTo(sectionId: string) {
    window.location.href = `/#${sectionId}`;
}

function formatDate(iso: string): string {
    return new Date(iso).toLocaleDateString('en-GB', {
        day: 'numeric', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit',
    });
}

function daysUntilPurge(deletedAt: string): number {
    const deleted = new Date(deletedAt).getTime();
    const purgeAt = deleted + 30 * 24 * 60 * 60 * 1000;
    return Math.max(0, Math.ceil((purgeAt - Date.now()) / (24 * 60 * 60 * 1000)));
}

export default function Inquiries() {
    const [ready, setReady] = useState(false);
    const [inquiries, setInquiries] = useState<Inquiry[]>([]);
    const [menuOpen, setMenuOpen] = useState(false);
    const [scrolled, setScrolled] = useState(false);
    const [filter, setFilter] = useState<FilterTab>('active');
    const [search, setSearch] = useState('');

    useEffect(() => {
        const onScroll = () => setScrolled(window.scrollY > 50);
        window.addEventListener('scroll', onScroll, { passive: true });
        return () => window.removeEventListener('scroll', onScroll);
    }, []);

    useEffect(() => {
        const observer = new IntersectionObserver(
            (entries) => {
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
    }, [ready, inquiries, filter, search]);

    useEffect(() => {
        supabase.auth.getSession().then(({ data: { session: s } }: { data: { session: Session | null } }) => {
            if (!s) { window.location.href = '/manage-8x7k'; return; }
            setReady(true);
        });

        const { data: { subscription } } = supabase.auth.onAuthStateChange((_event: string, s: Session | null) => {
            if (!s) window.location.href = '/manage-8x7k';
        });

        return () => subscription.unsubscribe();
    }, []);

    const fetchInquiries = useCallback(async () => {
        const { data } = await supabase
            .from('inquiries')
            .select('*')
            .order('created_at', { ascending: false });
        if (data) {
            const filtered = data.filter((i: Inquiry) => {
                if (i.status === 'deleted' && i.deleted_at) {
                    return daysUntilPurge(i.deleted_at) > 0;
                }
                return true;
            });
            setInquiries(filtered);
        }
    }, []);

    useEffect(() => {
        if (ready) fetchInquiries();
    }, [ready, fetchInquiries]);

    const updateStatus = async (id: string, newStatus: InquiryStatus) => {
        const updates: Record<string, unknown> = { status: newStatus };
        if (newStatus === 'deleted') {
            updates.deleted_at = new Date().toISOString();
            updates.archived_at = null;
        } else if (newStatus === 'archived') {
            updates.archived_at = new Date().toISOString();
            updates.deleted_at = null;
        } else {
            updates.deleted_at = null;
            updates.archived_at = null;
        }

        const { error } = await supabase.from('inquiries').update(updates).eq('id', id);
        if (!error) {
            setInquiries(prev => prev.map(i =>
                i.id === id
                    ? { ...i, status: newStatus, deleted_at: updates.deleted_at as string | null, archived_at: updates.archived_at as string | null }
                    : i
            ));
        }
    };

    const handleLogout = async () => {
        if (!window.confirm('Are you sure you want to sign out?')) return;
        await supabase.auth.signOut();
        window.location.href = '/manage-8x7k';
    };


    const byStatus = filter === 'all' ? inquiries : inquiries.filter(i => i.status === filter);

    const filtered = byStatus.filter(i => {
        if (!search.trim()) return true;
        const q = search.toLowerCase();
        return i.name.toLowerCase().includes(q)
            || i.email.toLowerCase().includes(q)
            || i.phone.toLowerCase().includes(q)
            || i.project.toLowerCase().includes(q);
    });


    const counts: Record<FilterTab, number> = {
        active: inquiries.filter(i => i.status === 'active').length,
        archived: inquiries.filter(i => i.status === 'archived').length,
        deleted: inquiries.filter(i => i.status === 'deleted').length,
        all: inquiries.length,
    };

    const emptyMessages: Record<FilterTab, { title: string; desc: string }> = {
        active: { title: 'No active inquiries', desc: 'When customers submit the contact form, their messages will show up here.' },
        archived: { title: 'No archived inquiries', desc: 'Inquiries you archive will appear here for reference.' },
        deleted: { title: 'No deleted inquiries', desc: 'Deleted inquiries appear here for 30 days before being permanently removed.' },
        all: { title: 'No inquiries yet', desc: 'When customers submit the contact form, their messages will show up here.' },
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
                        <button onClick={handleLogout} className="nav-link" style={{ color: 'var(--color-accent)' }}>
                            <LogOut size={14} style={{ display: 'inline', verticalAlign: '-2px', marginRight: '4px' }} />
                            Sign Out
                        </button>
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
                    <button onClick={() => { handleLogout(); setMenuOpen(false); }} className="mobile-nav-link" style={{ color: 'var(--color-accent)' }}>
                        Sign Out
                    </button>
                </div>
            </div>


            <section className="inq-section">
                <div className="container">
                    <div className="section-header reveal">
                        <p className="section-label">Submissions</p>
                        <h2 className="section-title">Customer Inquiries</h2>
                        <p className="section-subtitle">
                            {counts.active} active, {counts.archived} archived, {counts.deleted} deleted
                        </p>
                    </div>


                    <div className="inq-search reveal reveal-delay-1">
                        <Search size={18} className="inq-search-icon" />
                        <input
                            type="text"
                            className="inq-search-input"
                            placeholder="Search by name, email, phone or project..."
                            value={search}
                            onChange={e => setSearch(e.target.value)}
                        />
                    </div>


                    <div className="inq-filters reveal reveal-delay-2">
                        {FILTER_TABS.map(tab => (
                            <button
                                key={tab.key}
                                className={`inq-filter-btn ${filter === tab.key ? 'active' : ''}`}
                                onClick={() => setFilter(tab.key)}
                            >
                                {tab.label}
                                <span className="inq-filter-count">{counts[tab.key]}</span>
                            </button>
                        ))}
                    </div>


                    {filtered.length === 0 ? (
                        <div className="inq-empty">
                            <Mail size={48} />
                            <h3>{search.trim() ? 'No results found' : emptyMessages[filter].title}</h3>
                            <p>{search.trim() ? `No inquiries match "${search}".` : emptyMessages[filter].desc}</p>
                        </div>
                    ) : (
                        <div className="inq-grid">
                            {filtered.map((inquiry, idx) => (
                                <div key={inquiry.id} className={`inq-card reveal reveal-delay-${(idx % 3) + 1} ${inquiry.status !== 'active' ? 'inq-card-muted' : ''}`}>

                                    {inquiry.status !== 'active' && (
                                        <div className={`inq-badge inq-badge-${inquiry.status}`}>
                                            {inquiry.status === 'archived' && <><Archive size={12} /> Archived</>}
                                            {inquiry.status === 'deleted' && (
                                                <>
                                                    <Trash2 size={12} />
                                                    Deleted
                                                    {inquiry.deleted_at && (
                                                        <span className="inq-badge-timer">
                                                            <Clock size={11} /> {daysUntilPurge(inquiry.deleted_at)}d left
                                                        </span>
                                                    )}
                                                </>
                                            )}
                                        </div>
                                    )}


                                    <div className="inq-customer">
                                        <div className="inq-avatar">
                                            {inquiry.name.charAt(0).toUpperCase()}
                                        </div>
                                        <div className="inq-customer-info">
                                            <h3 className="inq-customer-name">{inquiry.name}</h3>
                                            <div className="inq-customer-details">
                                                <div className="inq-detail">
                                                    <Mail size={14} />
                                                    <span>{inquiry.email}</span>
                                                </div>
                                                <div className="inq-detail">
                                                    <Phone size={14} />
                                                    <span>{inquiry.phone}</span>
                                                </div>
                                                <div className="inq-detail">
                                                    <Calendar size={14} />
                                                    <span>{formatDate(inquiry.created_at)}</span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>


                                    <div className="inq-project-block">
                                        <h4 className="inq-project-label">
                                            <User size={14} />
                                            Project Details
                                        </h4>
                                        <p className="inq-project-text">{inquiry.project}</p>
                                    </div>


                                    <div className="inq-card-actions">
                                        {inquiry.status === 'active' && (
                                            <>
                                                <button className="inq-action-btn inq-action-archive" onClick={() => updateStatus(inquiry.id, 'archived')}>
                                                    <Archive size={14} /> Archive
                                                </button>
                                                <button className="inq-action-btn inq-action-delete" onClick={() => updateStatus(inquiry.id, 'deleted')}>
                                                    <Trash2 size={14} /> Delete
                                                </button>
                                            </>
                                        )}
                                        {inquiry.status === 'archived' && (
                                            <>
                                                <button className="inq-action-btn inq-action-restore" onClick={() => updateStatus(inquiry.id, 'active')}>
                                                    <RotateCcw size={14} /> Restore
                                                </button>
                                                <button className="inq-action-btn inq-action-delete" onClick={() => updateStatus(inquiry.id, 'deleted')}>
                                                    <Trash2 size={14} /> Delete
                                                </button>
                                            </>
                                        )}
                                        {inquiry.status === 'deleted' && (
                                            <button className="inq-action-btn inq-action-restore" onClick={() => updateStatus(inquiry.id, 'active')}>
                                                <RotateCcw size={14} /> Restore
                                            </button>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
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
