import { useState, useEffect } from 'react';
import { Menu, X, Phone, Mail, MapPin, ChevronRight, Hammer, Home, TreePine, Wrench, ArrowRight } from 'lucide-react';
import { supabase } from './lib/supabase';
import './App.css';

function App() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [activeSection, setActiveSection] = useState('home');
  const [scrolled, setScrolled] = useState(false);
  const [formStatus, setFormStatus] = useState<'idle' | 'submitting' | 'success' | 'error'>('idle');

  // Track scroll for navbar styling
  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 50);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Smooth scroll function
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
      image: '/images/service_furniture.jpg'
    },
    {
      icon: <TreePine size={32} />,
      title: 'Outdoor Structures',
      description: 'Decking, pergolas, cladding and exterior joinery built to withstand the elements.',
      image: '/images/service_outdoor.jpg'
    },
    {
      icon: <Wrench size={32} />,
      title: 'Repairs & Restoration',
      description: 'Doors, floors, stairs and timber restoration brought back to life with care.',
      image: '/images/service_repairs.jpg'
    },
    {
      icon: <Hammer size={32} />,
      title: 'Fitted Storage',
      description: 'Wardrobes, alcove units and wall-to-wall cabinetry that maximises every inch.',
      image: '/images/service_storage.jpg'
    }
  ];

  const projects = [
    { title: 'Modern Kitchen', image: '/images/project_kitchen_a.jpg', category: 'Kitchen' },
    { title: 'Alcove Shelving', image: '/images/project_alcove_a.jpg', category: 'Storage' },
    { title: 'Outdoor Deck', image: '/images/project_deck_a.jpg', category: 'Outdoor' },
    { title: 'Staircase Restoration', image: '/images/project_stairs_a.jpg', category: 'Restoration' },
    { title: 'Timber Detail', image: '/images/project_kitchen_b.jpg', category: 'Joinery' },
    { title: 'Deck Detail', image: '/images/project_deck_b.jpg', category: 'Outdoor' },
  ];

  return (
    <div className="app">
      {/* Fixed Navigation */}
      <nav className={`navbar ${scrolled ? 'scrolled' : ''}`}>
        <div className="nav-container">
          <button
            className="logo"
            onClick={() => scrollToSection('home')}
          >
            MACE REVAMP EB LTD
          </button>

          {/* Desktop Nav */}
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

      {/* Hero Section */}
      <section id="home" className="hero">
        <div className="hero-bg">
          <img src="/images/hero_portrait.jpg" alt="Master carpenter at work" />
          <div className="hero-overlay" />
        </div>
        <div className="hero-content">
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

      {/* About Section */}
      <section id="about" className="about">
        <div className="container">
          <div className="about-grid">
            <div className="about-image">
              <img src="/images/feature_precision.jpg" alt="Precision craftsmanship" />
            </div>
            <div className="about-content">
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
                <div className="stat">
                  <span className="stat-number">15+</span>
                  <span className="stat-label">Years Experience</span>
                </div>
                <div className="stat">
                  <span className="stat-number">500+</span>
                  <span className="stat-label">Projects Completed</span>
                </div>
                <div className="stat">
                  <span className="stat-number">100%</span>
                  <span className="stat-label">Satisfaction</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Services Section */}
      <section id="services" className="services">
        <div className="container">
          <div className="section-header">
            <p className="section-label">What We Do</p>
            <h2 className="section-title">Our Services</h2>
            <p className="section-subtitle">
              From custom furniture to outdoor structures, we deliver quality craftsmanship for every project.
            </p>
          </div>

          <div className="services-grid">
            {services.map((service, index) => (
              <div key={index} className="service-card">
                <div className="service-image">
                  <img src={service.image} alt={service.title} />
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

      {/* Work/Portfolio Section */}
      <section id="work" className="work">
        <div className="container">
          <div className="section-header">
            <p className="section-label">Portfolio</p>
            <h2 className="section-title">Our Recent Work</h2>
            <p className="section-subtitle">
              Browse through our latest projects and see the quality of our craftsmanship.
            </p>
          </div>

          <div className="work-grid">
            {projects.map((project, index) => (
              <div key={index} className="work-card">
                <div className="work-image">
                  <img src={project.image} alt={project.title} />
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

      {/* Contact Section */}
      <section id="contact" className="contact">
        <div className="container">
          <div className="contact-grid">
            <div className="contact-info">
              <p className="section-label">Get In Touch</p>
              <h2 className="section-title">Let's Build Something Solid</h2>
              <p className="contact-text">
                Tell us what you need. We'll reply within 1–2 business days with next steps and a rough estimate.
              </p>

              <div className="contact-details">
                <div className="contact-item">
                  <div className="contact-icon">
                    <Mail size={20} />
                  </div>
                  <div>
                    <span className="contact-label">Email</span>
                    <a href="mailto:hello@macerevamp.co.uk">hello@macerevamp.co.uk</a>
                  </div>
                </div>

                <div className="contact-item">
                  <div className="contact-icon">
                    <Phone size={20} />
                  </div>
                  <div>
                    <span className="contact-label">Phone</span>
                    <a href="tel:+442079460958">+44 (0)20 7946 0958</a>
                  </div>
                </div>

                <div className="contact-item">
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

            <div className="contact-form-wrapper">
              <form
                className="contact-form"
                onSubmit={async (e) => {
                  e.preventDefault();
                  setFormStatus('submitting');

                  const form = e.target as HTMLFormElement;
                  const name = (form.elements.namedItem('name') as HTMLInputElement).value;
                  const email = (form.elements.namedItem('email') as HTMLInputElement).value;
                  const phone = (form.elements.namedItem('phone') as HTMLInputElement).value;
                  const project = (form.elements.namedItem('project') as HTMLTextAreaElement).value;

                  try {
                    const { error } = await supabase
                      .from('inquiries')
                      .insert([
                        { name, email, phone, project }
                      ]);

                    if (!error) {
                      setFormStatus('success');
                      form.reset();
                      setTimeout(() => setFormStatus('idle'), 3000);
                    } else {
                      console.error("Supabase insert error:", error);
                      setFormStatus('error');
                    }
                  } catch (error) {
                    console.error("Form submission error:", error);
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
                    required
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="phone">Phone Number</label>
                  <input
                    type="tel"
                    id="phone"
                    name="phone"
                    placeholder="+44 123 456 7890"
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="project">Project Details</label>
                  <textarea
                    id="project"
                    name="project"
                    rows={4}
                    placeholder="Tell us about your project..."
                    required
                  />
                </div>

                {formStatus === 'error' && (
                  <div className="error-message" style={{ color: '#ef4444', marginBottom: '1rem', padding: '0.75rem', backgroundColor: '#fee2e2', borderRadius: '4px', border: '1px solid #f87171' }}>
                    Failed to send message. Please try again later.
                  </div>
                )}

                <button
                  type="submit"
                  className={`btn btn-primary btn-full ${formStatus === 'error' ? 'btn-error' : ''}`}
                  disabled={formStatus === 'submitting'}
                  style={formStatus === 'error' ? { backgroundColor: '#ef4444', borderColor: '#ef4444' } : {}}
                >
                  {formStatus === 'idle' || formStatus === 'error' ? (
                    <>Send Message <ArrowRight size={18} /></>
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

      {/* Footer */}
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
