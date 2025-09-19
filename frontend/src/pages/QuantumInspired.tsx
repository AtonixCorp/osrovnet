import React from 'react';
import QuantumInspiredPanel from '../components/QuantumInspiredPanel';

const QuantumInspiredPage: React.FC = () => {
  return (
    <div className="page-container">
      <h1>Quantum-Inspired Analytics</h1>
      <p>Run quantum-inspired simulations (classical approximations) for threat modeling and graph analysis.</p>
      <QuantumInspiredPanel />
    </div>
  );
};

export default QuantumInspiredPage;
