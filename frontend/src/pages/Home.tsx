import React from 'react';
import { useAuth } from '../auth/AuthProvider';
import './HomePage.css'; // Optional: for custom styling

const HomePage = () => {
  // Home page is informational; newsletter handled in global Footer component.

  const { user } = useAuth();

  const handleLaunch = (e: React.MouseEvent) => {
    e.preventDefault();
    if (user) {
      // go to dashboard (internal view)
      window.location.hash = '/dashboard';
    } else {
      // redirect visitors to signup
      window.location.hash = '/signup';
    }
  };

  return (
    <div className="homepage-container">
      <header className="hero-section">
        <h1>Osrovnet – Network Security Platform</h1>
        <p>
          AtonixCorp’s flagship solution for sovereign network defense, threat intelligence,
          and infrastructure resilience. Built for mission-critical environments and autonomous systems.
        </p>
  <a href="#/" onClick={handleLaunch} className="cta-button">Launch Dashboard</a>
      </header>

      <section className="features-section">
        <h2>🚀 Platform Features</h2>

        <div className="feature-block">
          <h3>🛡️ Network Security</h3>
          <ul>
            <li>Real-time network monitoring and analysis</li>
            <li>Advanced port scanning and vulnerability assessment</li>
            <li>Network topology mapping and visualization</li>
            <li>Intrusion detection and prevention systems</li>
            <li>Traffic analysis and pattern recognition</li>
          </ul>
        </div>

        <div className="feature-block">
          <h3>🎯 Threat Intelligence</h3>
          <ul>
            <li>Real-time threat feed integration</li>
            <li>IOC (Indicators of Compromise) management</li>
            <li>Threat hunting and analysis tools</li>
            <li>Automated threat response systems</li>
            <li>Threat landscape visualization</li>
          </ul>
        </div>

        <div className="feature-block">
          <h3>🏗️ Infrastructure Resilience</h3>
          <ul>
            <li>Health Monitoring: CPU, memory, disk, and network</li>
            <li>Automated Backup: Scheduled, encrypted backups</li>
            <li>Disaster Recovery: Planning, testing, and execution</li>
            <li>Maintenance Management: Change control and logs</li>
            <li>Alerting System: Configurable alerts and escalation</li>
          </ul>
        </div>
      </section>

      <footer className="footer-section">
        <p>© {new Date().getFullYear()} AtonixCorp. All rights reserved.</p>
        <nav>
          <a href="#/documentation">Documentation</a>
          <a href="#/support">Support</a>
          <a href="#/login">Sign In</a>
        </nav>
      </footer>
    </div>
  );
};

export default HomePage;
