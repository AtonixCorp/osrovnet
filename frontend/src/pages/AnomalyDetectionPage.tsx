import React, { useState } from 'react';
import {
  Box,
  Typography,
  Grid,
  Paper,
  Button,
  Divider,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions
} from '@mui/material';
import osrovnetApi from '../api/osrovnetApi';

export default function AnomalyDetectionPage() {
  const [openMap, setOpenMap] = useState(false);
  const [mapData, setMapData] = useState<any>(null);
  const [loadingTrace, setLoadingTrace] = useState(false);

  const openBehaviorMap = async () => {
    setOpenMap(true);
    try {
      // fetch some events as a proxy for nodes/edges (mocking for now)
      const events = await osrovnetApi.Analytics.events('?limit=50');
      // lightweight mock: create nodes from unique hosts
      const hosts = Array.from(new Set(events.map((e: any) => e.host || e.source || e.actor || '0'))).slice(0, 10);
      const nodes = hosts.map((h: any, i: number) => i);
      const edges = nodes.slice(0, Math.max(0, nodes.length - 1)).map((n: number, i: number) => [n, n + 1]);
      setMapData({ nodes, edges });
    } catch (e) {
      setMapData({ nodes: [0], edges: [] });
    }
  };

  const closeBehaviorMap = () => {
    setOpenMap(false);
    setMapData(null);
  };

  const traceMovement = async () => {
    setLoadingTrace(true);
    try {
      const payload = { technique: 'qgraph', params: { edges: [[0,1],[1,2],[2,3],[1,4]], start: 0, depth: 4 } };
      const res = await osrovnetApi.QuantumInspired.run(payload);
      // Display result in the behavior map modal for quick review
      setMapData(res || { nodes: [0], edges: [] });
      setOpenMap(true);
    } catch (e) {
      console.error('Trace error', e);
    } finally {
      setLoadingTrace(false);
    }
  };

  const launchInvestigation = () => {
    // open a forensic tool URL in a new tab - replace with your real forensics URL
    window.open('/forensics/launch/', '_blank');
  };
  return (
    <Box sx={{ p: 4, backgroundColor: '#f4f6f8', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: '#1a237e' }}>
        Anomaly Detection
      </Typography>

      <Typography variant="body1" sx={{ mb: 3, color: '#555' }}>
        Detect behavioral anomalies, trace lateral movement, and investigate suspicious activity with forensic precision.
        This module empowers analysts to identify deviations from baseline behavior and respond with clarity.
      </Typography>

      <Divider sx={{ mb: 3 }} />

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #4caf50' }}>
            <Typography variant="h6">🧠 Behavioral Analytics</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Monitor user and system behavior to detect deviations from normal patterns. Supports time-series modeling,
              peer group analysis, and adaptive baselining.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="success" onClick={openBehaviorMap}>View Behavior Map</Button>
          </Paper>
        </Grid>
            {/* Behavior Map Modal */}
            <Dialog open={openMap} onClose={closeBehaviorMap} fullWidth maxWidth="md">
              <DialogTitle>Behavior Map</DialogTitle>
              <DialogContent>
                <Box sx={{ width: '100%', height: 420, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                  {mapData ? (
                    <svg width={600} height={380} style={{ border: '1px solid #eee' }}>
                      {mapData.edges && mapData.edges.map((e: any, idx: number) => {
                        const cx = (i: number) => 50 + (i % 5) * 100;
                        const cy = (i: number) => 50 + Math.floor(i / 5) * 100;
                        return <line key={idx} x1={cx(e[0])} y1={cy(e[0])} x2={cx(e[1])} y2={cy(e[1])} stroke="#1976d2" strokeWidth={2} />;
                      })}
                      {mapData.nodes && mapData.nodes.map((n: number) => (
                        <g key={n}>
                          <circle cx={50 + (n % 5) * 100} cy={50 + Math.floor(n / 5) * 100} r={18} fill="#1976d2" />
                          <text x={50 + (n % 5) * 100} y={50 + Math.floor(n / 5) * 100 + 5} fontSize={12} textAnchor="middle" fill="#fff">{n}</text>
                        </g>
                      ))}
                    </svg>
                  ) : (
                    <Typography>Loading map...</Typography>
                  )}
                </Box>
              </DialogContent>
              <DialogActions>
                <Button onClick={closeBehaviorMap}>Close</Button>
              </DialogActions>
            </Dialog>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #f44336' }}>
            <Typography variant="h6">🔀 Lateral Movement Detection</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Trace unauthorized access across systems and zones. Visualize movement paths and identify privilege escalation attempts.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="error" onClick={traceMovement} disabled={loadingTrace}>{loadingTrace ? 'Tracing...' : 'Trace Movement'}</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #2196f3' }}>
            <Typography variant="h6">🔍 Forensic Tools</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Investigate anomalies with packet-level inspection, log correlation, and timeline reconstruction.
              Supports exportable evidence for compliance and legal review.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="primary" onClick={launchInvestigation}>Launch Investigation</Button>
          </Paper>
        </Grid>

        <Grid item xs={12}>
          <Paper elevation={2} sx={{ p: 3, borderLeft: '6px solid #9c27b0' }}>
            <Typography variant="h6">📝 Analyst Notes</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Document findings, hypotheses, and escalation decisions. Notes are timestamped and linked to anomaly events for audit and review.
            </Typography>
            <TextField
              label="Add a note"
              multiline
              rows={4}
              fullWidth
              variant="outlined"
              sx={{ mt: 2 }}
              placeholder="e.g. This anomaly originated from an internal endpoint with elevated privileges..."
            />
            <Button variant="contained" sx={{ mt: 2 }} color="secondary">Save Note</Button>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}