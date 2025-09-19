import React from 'react';
import './VulnerabilityPage.css';

const VulnerabilityPage = () => {
  return (
    <div className="page-container">
      <h1>⚠️ Vulnerability Center</h1>
      <p>
        The Vulnerability Center is your command post for identifying, tracking, and remediating security flaws across your infrastructure. Osrovnet provides real-time visibility and actionable intelligence to stay ahead of threats.
      </p>

      <section>
        <h2>🔍 Capabilities</h2>
        <ul>
          <li>Automated vulnerability scanning and severity tagging</li>
          <li>Zero-day tracking and exploit prediction</li>
          <li>Patch intelligence and remediation workflows</li>
          <li>Compliance mapping to NIST, ISO, and GDPR</li>
          <li>Historical comparison and drift detection</li>
        </ul>
      </section>

      <section>
        <h2>🧠 Strategic Response</h2>
        <p>
          Vulnerabilities are not just technical flaws—they’re strategic risks. Osrovnet helps you prioritize based on asset criticality, threat context, and operational impact.
        </p>
      </section>
    </div>
  );
};

export default VulnerabilityPage;
