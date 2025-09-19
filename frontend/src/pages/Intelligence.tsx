import React from 'react';
import './IntelligenceCenter.css'; // Optional: for styling

const IntelligenceCenter = () => {
  return (
    <div className="intelligence-center-container">
      <header className="intelligence-header">
        <h1>🎯 Intelligence Center</h1>
        <p>
          The Intelligence Center is Osrovnet’s strategic hub for threat detection, IOC management,
          and automated response. Built for sovereign systems and mission-critical environments,
          it transforms raw telemetry into actionable insight.
        </p>
      </header>

      <section className="intelligence-section">
        <h2>🧠 Key Capabilities</h2>

        <div className="feature-block">
          <h3>🔍 Threat Feed Integration</h3>
          <ul>
            <li>Real-time ingestion of global threat intelligence feeds</li>
            <li>Automatic enrichment of scan results with known threat signatures</li>
            <li>Severity tagging and contextual metadata</li>
          </ul>
        </div>

        <div className="feature-block">
          <h3>🧩 IOC Management</h3>
          <ul>
            <li>Centralized repository for Indicators of Compromise</li>
            <li>Tagging, versioning, and lifecycle tracking</li>
            <li>Cross-reference with network scans and logs</li>
          </ul>
        </div>

        <div className="feature-block">
          <h3>🧨 Threat Hunting Tools</h3>
          <ul>
            <li>Manual and automated search across assets</li>
            <li>Behavioral heuristics and anomaly detection</li>
            <li>Kill chain mapping and adversary emulation</li>
          </ul>
        </div>

        <div className="feature-block">
          <h3>📊 Threat Landscape Visualization</h3>
          <ul>
            <li>Interactive dashboards showing threat clusters and severity</li>
            <li>Time-based heatmaps and attack vector overlays</li>
            <li>Filter by asset, region, protocol, or threat type</li>
          </ul>
        </div>

        <div className="feature-block">
          <h3>⚙️ Automated Response Engine</h3>
          <ul>
            <li>Trigger-based containment and alerting</li>
            <li>Integration with SOAR platforms and playbooks</li>
            <li>Escalation paths based on asset criticality</li>
          </ul>
        </div>
      </section>

      <footer className="intelligence-footer">
        <p>© {new Date().getFullYear()} AtonixCorp – Intelligence Center Module</p>
      </footer>
    </div>
  );
};

export default IntelligenceCenter;
