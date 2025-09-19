import React, { useState } from 'react';
import Api from '../api/osrovnetApi';

export default function DemoControls() {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const demoDataset = { rows: [[1,2,3],[2,3,4],[10,10,10]] };

  const runDetection = async () => {
    setLoading(true);
    setResult(null);
    try {
      const res = await Api.SecurityAnalytics.detect(1, demoDataset);
      setResult(res);
    } catch (err: any) {
      setResult({ error: err.message || err });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{padding: 12}}>
      <h3>Security Analytics Demo</h3>
      <button onClick={runDetection} disabled={loading}>{loading ? 'Running...' : 'Run Anomaly Detection (demo)'}</button>
      <pre style={{whiteSpace: 'pre-wrap', marginTop: 12}}>{result ? JSON.stringify(result, null, 2) : 'No result yet'}</pre>
    </div>
  );
}
