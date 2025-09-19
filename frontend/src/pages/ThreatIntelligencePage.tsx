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

export default function ThreatIntelligencePage() {
  return (
    <Box sx={{ p: 4, backgroundColor: '#f4f6f8', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: '#1a237e' }}>
        Threat Intelligence
      </Typography>

      <Typography variant="body1" sx={{ mb: 3, color: '#555' }}>
        Integrate external feeds, flag malicious indicators, and enrich scan results with contextual threat data.
        This module empowers analysts to visualize threat posture, manage IOCs, and automate response workflows.
      </Typography>

      <Divider sx={{ mb: 3 }} />

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #2196f3' }}>
            <Typography variant="h6">🌐 External Feed Integration</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Connect to STIX/TAXII feeds, proprietary threat sources, or community intelligence hubs.
              Automatically ingest and tag indicators for real-time enrichment.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="primary">Configure Feeds</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #f44336' }}>
            <Typography variant="h6">🚨 IOC Management</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Flag, tag, and track Indicators of Compromise (IOCs) across your network. Assign severity, source,
              and lifecycle status for each indicator.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="error">Manage IOCs</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #4caf50' }}>
            <Typography variant="h6">🧠 Threat Enrichment</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Enrich scan results with threat context—geolocation, malware family, attack vector, and known exploits.
              Supports automated tagging and correlation.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="success">Enrich Results</Button>
          </Paper>
        </Grid>

        <Grid item xs={12}>
          <Paper elevation={2} sx={{ p: 3, borderLeft: '6px solid #9c27b0' }}>
            <Typography variant="h6">📝 Analyst Notes</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Add contextual notes to threat clusters, feed sources, or IOC entries. Useful for internal review,
              escalation decisions, and audit documentation.
            </Typography>
            <TextField
              label="Add a note"
              multiline
              rows={4}
              fullWidth
              variant="outlined"
              sx={{ mt: 2 }}
              placeholder="e.g. This IOC is linked to a known phishing campaign targeting finance sector..."
            />
            <Button variant="contained" sx={{ mt: 2 }} color="secondary">Save Note</Button>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}