import React, { useEffect, useState } from 'react';
import { Box, Button, Select, MenuItem, TextField, Typography, Paper } from '@mui/material';
import osrovnetApi from '../api/osrovnetApi';

type Technique = { id: string; name: string; description?: string };

const TECHNIQUES: Technique[] = [
  { id: 'grover', name: 'Grover Search Simulation', description: 'Heuristic speedup for search problems' },
  { id: 'qwalk', name: 'Quantum Walks', description: 'Graph-based walk heuristics for anomaly scoring' },
  { id: 'varc', name: 'Variational Circuits', description: 'Parametric optimizer for feature selection' },
  { id: 'qgraph', name: 'Quantum-Inspired Graph Traversal', description: 'Lateral movement / path analysis' },
];

export default function QuantumInspiredPanel() {
  const [tech, setTech] = useState<string>('qgraph');
  const [params, setParams] = useState<string>('{}');
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<any>(null);

  useEffect(() => {
    // prefill simple params for qgraph
    if (tech === 'qgraph') {
      setParams(JSON.stringify({ edges: [[0,1],[1,2],[2,3],[1,4]], start: 0, depth: 4 }, null, 2));
    } else {
      setParams('{}');
    }
  }, [tech]);

  const run = async () => {
    setRunning(true);
    setResult(null);
    try {
  const payload = { technique: tech, params: JSON.parse(params) };
  const res = await osrovnetApi.QuantumInspired.run(payload);
      setResult(res);
    } catch (e: any) {
      setResult({ error: e?.body || e?.message || String(e) });
    } finally {
      setRunning(false);
    }
  };

  const renderGraph = (data: any) => {
    if (!data || !data.nodes) return null;
    const nodes: number[] = data.nodes;
    const edges: [number, number][] = data.edges || [];
    const size = 300;
    const cx = (i: number) => 40 + (i % 5) * 50;
    const cy = (i: number) => 40 + Math.floor(i / 5) * 50;
    return (
      <svg width={size} height={size} style={{ border: '1px solid #eee' }}>
        {edges.map((e, idx) => (
          <line key={idx} x1={cx(e[0])} y1={cy(e[0])} x2={cx(e[1])} y2={cy(e[1])} stroke="#1976d2" strokeWidth={2} />
        ))}
        {nodes.map((n) => (
          <g key={n}>
            <circle cx={cx(n)} cy={cy(n)} r={10} fill="#1976d2" />
            <text x={cx(n)} y={cy(n) + 4} fontSize={10} textAnchor="middle" fill="#fff">{n}</text>
          </g>
        ))}
      </svg>
    );
  };

  return (
    <Paper sx={{ p: 2 }}>
      <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
        <Box sx={{ flex: 1 }}>
          <Typography variant="subtitle1">Technique</Typography>
          <Select fullWidth value={tech} onChange={(e) => setTech(String(e.target.value))}>
            {TECHNIQUES.map((t) => (
              <MenuItem value={t.id} key={t.id}>{t.name}</MenuItem>
            ))}
          </Select>

          <Typography variant="subtitle1" sx={{ mt: 2 }}>Parameters (JSON)</Typography>
          <TextField multiline minRows={6} fullWidth value={params} onChange={(e) => setParams(e.target.value)} />

          <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
            <Button variant="contained" onClick={run} disabled={running}>Run</Button>
            <Button variant="outlined" onClick={() => { setParams('{}'); setResult(null); }}>Reset</Button>
          </Box>
        </Box>

        <Box sx={{ width: 360 }}>
          <Typography variant="subtitle1">Result</Typography>
          <Box sx={{ maxHeight: 360, overflow: 'auto', p: 1, border: '1px solid #eee', borderRadius: 1 }}>
            <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{JSON.stringify(result, null, 2)}</pre>
          </Box>
          <Box sx={{ mt: 2 }}>
            {tech === 'qgraph' && renderGraph(result)}
          </Box>
        </Box>
      </Box>
    </Paper>
  );
}
