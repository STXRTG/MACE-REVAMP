import { useState, useEffect, useRef } from 'react';
import { Menu, X, Phone, Mail, MapPin, ChevronRight, Hammer, Home, TreePine, Wrench, ArrowRight, Loader2 } from 'lucide-react';
import { supabase } from './lib/supabase';
import { solveChallenge } from './lib/pow';
import './App.css';

function App() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [activeSection, setActiveSection] = useState('home');
  const [scrolled, setScrolled] = useState(false);
  const [formStatus, setFormStatus] = useState<'idle' | 'submitting' | 'solving' | 'success' | 'error'>('idle');
  const [formError, setFormError] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const mobileMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 50);
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
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
  }, []);

  // Focus trap for mobile menu
  useEffect(() => {
    if (!menuOpen) return;

    const menuEl = mobileMenuRef.current;
    if (!menuEl) return;

    const focusableEls = menuEl.querySelectorAll<HTMLElement>('button, [href], input, [tabindex]:not([tabindex="-1"])');
    if (focusableEls.length === 0) return;

    const firstEl = focusableEls[0];
    const lastEl = focusableEls[focusableEls.length - 1];

    firstEl.focus();

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setMenuOpen(false);
        return;
      }
      if (e.key !== 'Tab') return;

      if (e.shiftKey) {
        if (document.activeElement === firstEl) {
          e.preventDefault();
          lastEl.focus();
        }
      } else {
        if (document.activeElement === lastEl) {
          e.preventDefault();
          firstEl.focus();
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [menuOpen]);

  const scrollToSection = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
      setActiveSection(id);
      setMenuOpen(false);
    }
  };

  const navItems = [
    { id: 'home', label: 'Home' },
    { id: 'about', label: 'About' },
    { id: 'services', label: 'Services' },
    { id: 'work', label: 'Our Work' },
    { id: 'contact', label: 'Contact' },
  ];

  const services = [
    {
      icon: <Home size={32} />,
      title: 'Custom Furniture',
      description: 'Built-in storage, media units, tables and seating designed around your space.',
      image: '/images/service_furniture.jpg',
      alt: 'Custom built-in furniture with clean woodwork and integrated storage'
    },
    {
      icon: <TreePine size={32} />,
      title: 'Outdoor Structures',
      description: 'Decking, pergolas, cladding and exterior joinery built to withstand the elements.',
      image: '/images/service_outdoor.jpg',
      alt: 'Outdoor timber decking and pergola structure in a garden setting'
    },
    {
      icon: <Wrench size={32} />,
      title: 'Repairs & Restoration',
      description: 'Doors, floors, stairs and timber restoration brought back to life with care.',
      image: '/images/service_repairs.jpg',
      alt: 'Restored wooden staircase showing detailed carpentry repair work'
    },
    {
      icon: <Hammer size={32} />,
      title: 'Fitted Storage',
      description: 'Wardrobes, alcove units and wall-to-wall cabinetry that maximises every inch.',
      image: '/images/service_storage.jpg',
      alt: 'Bespoke fitted wardrobe with wall-to-wall cabinetry in a bedroom'
    }
  ];

  const projects = [
    { title: 'Modern Kitchen', image: '/images/project_kitchen_a.jpg', category: 'Kitchen', alt: 'Completed modern kitchen renovation with custom wooden cabinetry' },
    { title: 'Alcove Shelving', image: '/images/project_alcove_a.jpg', category: 'Storage', alt: 'Bespoke alcove shelving unit fitted into a living room wall' },
    { title: 'Outdoor Deck', image: '/images/project_deck_a.jpg', category: 'Outdoor', alt: 'Large outdoor timber deck installed in a residential garden' },
    { title: 'Staircase Restoration', image: '/images/project_stairs_a.jpg', category: 'Restoration', alt: 'Fully restored period staircase with refinished wooden banister' },
    { title: 'Timber Detail', image: '/images/project_kitchen_b.jpg', category: 'Joinery', alt: 'Close-up of hand-finished timber joinery detail in a kitchen' },
    { title: 'Deck Detail', image: '/images/project_deck_b.jpg', category: 'Outdoor', alt: 'Detail view of precision-cut garden decking boards' },
  ];

  return (
    <div className="app">

      <nav className={`navbar ${scrolled ? 'scrolled' : ''}`}>
        <div className="nav-container">
          <button
            className="logo"
            onClick={() => scrollToSection('home')}
          >
            MACE REVAMP EB LTD
          </button>

          <div className="nav-links desktop">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                className={`nav-link ${activeSection === item.id ? 'active' : ''}`}
              >
                {item.label}
              </button>
            ))}
          </div>

          <button
            className="menu-btn"
            onClick={() => setMenuOpen(!menuOpen)}
            aria-label="Toggle menu"
          >
            {menuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>
      </nav>

      <div ref={mobileMenuRef} className={`mobile-menu ${menuOpen ? 'open' : ''}`}>
        <div className="mobile-menu-content">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              className={`mobile-nav-link ${activeSection === item.id ? 'active' : ''}`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      <section id="home" className="hero">
        <div className="hero-bg">
          <img src="/images/hero_portrait.jpg" alt="Professional carpenter hand-finishing a timber joint in the workshop" />
          <div className="hero-overlay" />
        </div>
        <div className="hero-content reveal visible">
          <p className="hero-tagline">LONDON — UK-WIDE</p>
          <h1 className="hero-title">
            Bespoke Carpentry<br />
            <span className="highlight">Built to Last</span>
          </h1>
          <p className="hero-description">
            Premium joinery, fitted furniture and custom woodwork for homes and commercial spaces.
            Quality craftsmanship you can trust.
          </p>
          <div className="hero-buttons">
            <button
              className="btn btn-primary"
              onClick={() => scrollToSection('contact')}
            >
              Get a Quote
              <ArrowRight size={18} />
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => scrollToSection('work')}
            >
              View Our Work
            </button>
          </div>
        </div>
        <div className="scroll-indicator">
          <span>Scroll to explore</span>
          <div className="scroll-arrow" />
        </div>
      </section>

      <section id="about" className="about">
        <div className="container">
          <div className="about-grid">
            <div className="about-image reveal">
              <img src="/images/feature_precision.jpg" alt="Close-up of precision woodworking tools and hand-cut timber joints" />
            </div>
            <div className="about-content reveal">
              <p className="section-label">About Us</p>
              <h2 className="section-title">Precision in Every Detail</h2>
              <p className="about-text">
                At MACE REVAMP EB LTD, we bring decades of carpentry expertise to every project.
                From first measurement to final fitting, we cut, joint and finish with
                workshop-grade accuracy.
              </p>
              <p className="about-text">
                Whether it's a custom kitchen, fitted wardrobes, or restoring a period staircase,
                we treat every piece of wood with the respect it deserves.
              </p>
              <div className="stats">
                <div className="stat reveal reveal-delay-1">
                  <span className="stat-number">15+</span>
                  <span className="stat-label">Years Experience</span>
                </div>
                <div className="stat reveal reveal-delay-2">
                  <span className="stat-number">500+</span>
                  <span className="stat-label">Projects Completed</span>
                </div>
                <div className="stat reveal reveal-delay-3">
                  <span className="stat-number">100%</span>
                  <span className="stat-label">Satisfaction</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="services" className="services">
        <div className="container">
          <div className="section-header reveal">
            <p className="section-label">What We Do</p>
            <h2 className="section-title">Our Services</h2>
            <p className="section-subtitle">
              From custom furniture to outdoor structures, we deliver quality craftsmanship for every project.
            </p>
          </div>

          <div className="services-grid">
            {services.map((service, index) => (
              <div key={index} className={`service-card reveal reveal-delay-${(index % 3) + 1}`}>
                <div className="service-image">
                  <img src={service.image} alt={service.alt} />
                </div>
                <div className="service-content">
                  <div className="service-icon">{service.icon}</div>
                  <h3 className="service-title">{service.title}</h3>
                  <p className="service-description">{service.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="work" className="work">
        <div className="container">
          <div className="section-header reveal">
            <p className="section-label">Portfolio</p>
            <h2 className="section-title">Our Recent Work</h2>
            <p className="section-subtitle">
              Browse through our latest projects and see the quality of our craftsmanship.
            </p>
          </div>

          <div className="work-grid">
            {projects.map((project, index) => (
              <div key={index} className={`work-card reveal reveal-delay-${(index % 3) + 1}`}>
                <div className="work-image">
                  <img src={project.image} alt={project.alt} />
                  <div className="work-overlay">
                    <span className="work-category">{project.category}</span>
                    <h3 className="work-title">{project.title}</h3>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="work-cta">
            <button
              className="btn btn-primary"
              onClick={() => scrollToSection('contact')}
            >
              Start Your Project
              <ChevronRight size={18} />
            </button>
          </div>
        </div>
      </section>

      <section id="contact" className="contact">
        <div className="container">
          <div className="contact-grid">
            <div className="contact-info reveal">
              <p className="section-label">Get In Touch</p>
              <h2 className="section-title">Let's Build Something Solid</h2>
              <p className="contact-text">
                Tell us what you need. We'll reply within 1–2 business days with next steps and a rough estimate.
              </p>

              <div className="contact-details">
                <div className="contact-item reveal reveal-delay-1">
                  <div className="contact-icon">
                    <Mail size={20} />
                  </div>
                  <div>
                    <span className="contact-label">Email</span>
                    <a href="mailto:hello@macerevamp.co.uk">hello@macerevamp.co.uk</a>
                  </div>
                </div>

                <div className="contact-item reveal reveal-delay-2">
                  <div className="contact-icon">
                    <Phone size={20} />
                  </div>
                  <div>
                    <span className="contact-label">Phone</span>
                    <a href="tel:+442079460958">+44 (0)20 7946 0958</a>
                  </div>
                </div>

                <div className="contact-item reveal reveal-delay-3">
                  <div className="contact-icon">
                    <MapPin size={20} />
                  </div>
                  <div>
                    <span className="contact-label">Location</span>
                    <span>London — UK-wide</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="contact-form-wrapper reveal">
              <form
                className="contact-form"
                onSubmit={async (e: React.FormEvent<HTMLFormElement>) => {
                  e.preventDefault();
                  setFormStatus('submitting');

                  const now = Date.now();
                  const RL_KEY = 'mace_last_submit';
                  const lastSubmit = parseInt(localStorage.getItem(RL_KEY) || '0', 10);
                  if (now - lastSubmit < 60000) {
                    const secsLeft = Math.ceil((60000 - (now - lastSubmit)) / 1000);
                    setFormError(`You've already sent a message recently. Please wait ${secsLeft} seconds before trying again.`);
                    setFormStatus('error');
                    return;
                  }

                  const form = e.target as HTMLFormElement;
                  const name = (form.elements.namedItem('name') as HTMLInputElement).value.trim();
                  const email = (form.elements.namedItem('email') as HTMLInputElement).value.trim();
                  const project = (form.elements.namedItem('project') as HTMLTextAreaElement).value.trim();

                  // Strip leading 0 for proper international format: 07123... → +447123...
                  const digits = phoneNumber.replace(/\D/g, '');
                  const normalised = digits.startsWith('0') ? digits.slice(1) : digits;
                  const phone = `+44${normalised}`;

                  if (name.length > 100 || email.length > 255 || project.length > 5000) {
                    setFormError('One or more fields exceed the maximum length. Please shorten your input and try again.');
                    setFormStatus('error');
                    return;
                  }

                  if (!/^[A-Za-z\s'\-]{2,}$/.test(name.trim())) {
                    setFormError('Please enter your full name using letters only (at least 2 characters).');
                    setFormStatus('error');
                    return;
                  }

                  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim())) {
                    setFormError('That doesn\'t look like a valid email. Please double-check and try again.');
                    setFormStatus('error');
                    return;
                  }

                  if (!digits || digits.length < 10 || digits.length > 11) {
                    setFormError('Please enter a valid UK phone number (10–11 digits after +44).');
                    setFormStatus('error');
                    return;
                  }

                  setFormStatus('solving');
                  try {
                    const formFingerprint = `${name}:${email}:${phone}:${project.substring(0, 50)}`;
                    await solveChallenge(formFingerprint);

                    // Direct database insert
                    const { error: insertError } = await supabase
                      .from('inquiries')
                      .insert([{
                        name,
                        email,
                        phone,
                        project,
                        status: 'active'
                      }]);

                    if (insertError) throw insertError;

                    localStorage.setItem(RL_KEY, Date.now().toString());
                    setFormStatus('success');
                    form.reset();
                    setPhoneNumber('');
                    setTimeout(() => setFormStatus('idle'), 5000);
                  } catch (err: any) {
                    console.error('Submission error:', err);
                    setFormError(err.message || 'Something went wrong. Please try again or email us directly.');
                    setFormStatus('error');
                  }
                }}
              >
                <div className="form-group">
                  <label htmlFor="name">Your Name</label>
                  <input
                    type="text"
                    id="name"
                    name="name"
                    placeholder="John Smith"
                    maxLength={100}
                    minLength={2}
                    pattern="[A-Za-z\s'\-]+"
                    title="Letters, spaces, hyphens and apostrophes only"
                    required
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="email">Email Address</label>
                  <input
                    type="email"
                    id="email"
                    name="email"
                    placeholder="john@example.com"
                    maxLength={255}
                    pattern="[^\s@]+@[^\s@]+\.[^\s@]{2,}"
                    title="Enter a valid email (e.g. name@company.com)"
                    required
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="phone">Phone Number</label>
                  <div className="phone-input-container">
                    <span className="phone-prefix">+44</span>
                    <input
                      type="tel"
                      id="phone"
                      name="phone"
                      placeholder="7123456789"
                      maxLength={13}
                      autoComplete="tel-national"
                      value={phoneNumber}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
                        const val = e.target.value;
                        // Allow only digits, spaces, and +
                        if (/^[0-9+\s]*$/.test(val)) {
                          setPhoneNumber(val);
                        }
                      }}
                      required
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label htmlFor="project">Project Details</label>
                  <textarea
                    id="project"
                    name="project"
                    rows={4}
                    placeholder="Tell us about your project..."
                    maxLength={5000}
                    required
                  />
                </div>



                {formStatus === 'error' && (
                  <div role="alert" aria-live="assertive" style={{ color: '#ef4444', margin: '0.75rem 0', padding: '0.75rem', backgroundColor: '#fee2e2', borderRadius: '4px', border: '1px solid #f87171', fontSize: '0.875rem' }}>
                    {formError || 'Something went wrong. Please try again later.'}
                  </div>
                )}

                <button
                  type="submit"
                  className={`btn btn-primary btn-full ${formStatus === 'error' ? 'btn-error' : ''}`}
                  disabled={formStatus === 'submitting' || formStatus === 'solving'}
                  style={formStatus === 'error' ? { backgroundColor: '#ef4444', borderColor: '#ef4444' } : {}}
                >
                  {formStatus === 'idle' || formStatus === 'error' ? (
                    <>Send Message <ArrowRight size={18} /></>
                  ) : formStatus === 'solving' ? (
                    <><Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} /> Verifying...</>
                  ) : formStatus === 'submitting' ? (
                    'Sending...'
                  ) : (
                    'Message Sent!'
                  )}
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
                {navItems.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => scrollToSection(item.id)}
                  >
                    {item.label}
                  </button>
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
            <p>© {new Date().getFullYear()} MACE REVAMP EB LTD. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
