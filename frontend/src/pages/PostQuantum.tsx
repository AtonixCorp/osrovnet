import React from 'react';
import PQCKeyGenerator from '../components/PQCKeyGenerator';

const PostQuantumPage: React.FC = () => {
  return (
    <div className="page-container">
      <h1>Post-Quantum Key Management</h1>
      <p>Generate and manage post-quantum keypairs. This feature requires optional PQC libraries on the server. If generation is not available, you'll see an instruction message.</p>
      <PQCKeyGenerator />
    </div>
  );
};

export default PostQuantumPage;
