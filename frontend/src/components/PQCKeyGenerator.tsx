import React, { useEffect, useState } from 'react';
import api from '../api/osrovnetApi';

type Algo = { name: string; description: string };

const PQCKeyGenerator: React.FC = () => {
  const [algorithms, setAlgorithms] = useState<Algo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string>('');
  const [name, setName] = useState('my-pqc-key');

  useEffect(() => {
    setLoading(true);
    api.request('/postquantum/algorithms/').then((data) => {
      setAlgorithms(data);
      if (data && data.length) setSelected(data[0].name);
    }).catch((e) => {
      setError(e.body?.detail || e.message || 'Failed to fetch algorithms');
    }).finally(() => setLoading(false));
  }, []);

  const [success, setSuccess] = useState<string | null>(null);

  async function generate() {
    setError(null);
    setSuccess(null);
    setLoading(true);
    try {
      const resp = await api.request('/postquantum/generate/', {
        method: 'POST',
        body: JSON.stringify({ algorithm: selected, name }),
      });
      // auto-download private key
      if (resp.private_key_b64) {
        const b = atob(resp.private_key_b64);
        const bytes = new Uint8Array(b.length);
        for (let i = 0; i < b.length; i++) bytes[i] = b.charCodeAt(i);
        const blob = new Blob([bytes], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${name}-private.key`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      }
      setSuccess('Key generated. Public key saved to server. Private key downloaded.');
    } catch (e: any) {
      setError(e.body?.detail || e.message || 'Error generating key');
    } finally { setLoading(false); }
  }

  return (
    <div className="pqc-generator">
      {loading && <div>Loading…</div>}
      {error && <div style={{ color: 'crimson' }}>{error}</div>}
      {!loading && (
        <div>
          {error && <div style={{ color: 'crimson' }}>{error}</div>}
          {success && <div style={{ color: 'green' }}>{success}</div>}
          <label>Algorithm</label>
          <select value={selected} onChange={e => setSelected(e.target.value)}>
            {algorithms.map(a => <option key={a.name} value={a.name}>{a.name} — {a.description}</option>)}
          </select>
          <div>
            <label>Key name</label>
            <input value={name} onChange={e => setName(e.target.value)} />
          </div>
          <button onClick={generate} disabled={!selected}>Generate keypair</button>
        </div>
      )}
    </div>
  );
};

export default PQCKeyGenerator;
