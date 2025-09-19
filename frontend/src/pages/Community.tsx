import React from 'react';
import './CommunityPage.css';

const CommunityPage = () => {
  return (
    <div className="page-container">
      <h1>🌍 Osrovnet Community</h1>
      <p>
        The Osrovnet Community is a global network of engineers, analysts, and strategists committed to advancing sovereign security infrastructure. Here, members share insights, collaborate on threat research, and shape the future of autonomous defense.
      </p>

      <section>
        <h2>🤝 What You’ll Find</h2>
        <ul>
          <li>Discussion forums on network security and threat intelligence</li>
          <li>Community-led vulnerability research and patch sharing</li>
          <li>Mentorship and technical advisory groups</li>
          <li>Editorial contributions to Osrovnet’s knowledge base</li>
        </ul>
      </section>

      <section>
        <h2>📬 Join the Conversation</h2>
        <p>
          Whether you're deploying Osrovnet in a sovereign data center or contributing to open-source modules, your voice matters. Connect with peers, share your expertise, and help shape resilient systems.
        </p>
      </section>
    </div>
  );
};

export default CommunityPage;
