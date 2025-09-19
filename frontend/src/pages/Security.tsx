import React from 'react';
import './SecurityPage.css';

const SecurityPage = () => {
  return (
    <div className="page-container">
      <h1>🔐 Security Overview</h1>
      <p>
        Osrovnet is built with uncompromising security standards—from protocol inspection to perimeter defense. Every module is engineered to detect, prevent, and respond to threats in real time.
      </p>

      <section>
        <h2>🛡️ Core Security Features</h2>
        <ul>
          <li>Real-time network monitoring and anomaly detection</li>
          <li>Advanced port scanning and service fingerprinting</li>
          <li>Intrusion detection and prevention systems (IDPS)</li>
          <li>Encrypted telemetry and tamper-proof logging</li>
          <li>Role-based access control and audit trails</li>
        </ul>
      </section>

      <section>
        <h2>🧠 Security Philosophy</h2>
        <p>
          Osrovnet treats security as a living system—adaptive, autonomous, and deeply integrated. From quantum-safe encryption to behavioral heuristics, every layer is designed to protect mission-critical infrastructure.
        </p>
      </section>
    </div>
  );
};

export default SecurityPage;
