import React from 'react';
import './SupportPage.css'; // Optional: for styling

const SupportPage = () => {
  return (
    <div className="support-page-container">
      <header className="support-header">
        <h1>📞 Osrovnet Support Center</h1>
        <p>
          Welcome to the Osrovnet Support Center. Whether you're troubleshooting a scan engine,
          configuring threat feeds, or preparing for compliance audits—we’re here to help.
        </p>
      </header>

      <section className="support-section">
        <h2>🛠 How Can We Assist You?</h2>
        <ul>
          <li><strong>Technical Support:</strong> Resolve issues with scans, telemetry, or dashboard performance.</li>
          <li><strong>Platform Setup:</strong> Get help configuring network targets, alerting systems, and integrations.</li>
          <li><strong>Threat Intelligence:</strong> Assistance with IOC management, feed integration, and hunting tools.</li>
          <li><strong>Compliance & Audit:</strong> Guidance on generating reports, mapping to NIST/ISO, and audit trails.</li>
        </ul>
      </section>

      <section className="contact-section">
        <h2>📬 Contact Us</h2>
        <p>Need direct assistance? Reach out through one of the following channels:</p>
        <ul>
          <li>Email: <a href="mailto:support@atonixcorp.com">support@atonixcorp.com</a></li>
          <li>Phone: +1 (800) SECURE-NET</li>
          <li>Live Chat: Available weekdays 9am–6pm EST</li>
          <li>Incident Hotline: For urgent breach or infrastructure issues</li>
        </ul>
      </section>

      <section className="resources-section">
        <h2>📚 Resources</h2>
        <ul>
          <li><a href="#/documentation">Documentation Portal</a></li>
          <li><a href="#/faq">Frequently Asked Questions</a></li>
          <li><a href="#/status">System Status Dashboard</a></li>
          <li><a href="#/tickets">Submit a Support Ticket</a></li>
        </ul>
      </section>

      <footer className="support-footer">
        <p>© {new Date().getFullYear()} AtonixCorp – Osrovnet Support Division</p>
      </footer>
    </div>
  );
};

export default SupportPage;
