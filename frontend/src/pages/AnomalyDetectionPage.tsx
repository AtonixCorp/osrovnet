import React from 'react';
import {
  Box,
  Typography,
  Grid,
  Paper,
  Button,
  Divider,
  TextField
} from '@mui/material';

export default function AnomalyDetectionPage() {
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
            <Button variant="outlined" sx={{ mt: 2 }} color="success">View Behavior Map</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #f44336' }}>
            <Typography variant="h6">🔀 Lateral Movement Detection</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Trace unauthorized access across systems and zones. Visualize movement paths and identify privilege escalation attempts.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="error">Trace Movement</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #2196f3' }}>
            <Typography variant="h6">🔍 Forensic Tools</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Investigate anomalies with packet-level inspection, log correlation, and timeline reconstruction.
              Supports exportable evidence for compliance and legal review.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="primary">Launch Investigation</Button>
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