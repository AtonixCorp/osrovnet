import React from 'react';
import { Box, Typography, Grid, Paper, Button } from '@mui/material';

export default function IncidentResponsePage() {
  return (
    <Box sx={{ p: 4, backgroundColor: '#f4f6f8', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: '#1a237e' }}>
        Incident Response
      </Typography>

      <Typography variant="body1" sx={{ mb: 3, color: '#555' }}>
        Manage security incidents with precision and speed. This module supports alert triage, automated playbooks, SOAR integration, and full case lifecycle tracking—ensuring your team responds with clarity and control.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #f44336' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>🚨 Alert Triage</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Prioritize alerts based on severity, asset impact, and threat classification. Filter by source, timestamp, or trust zone.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="error">View Alerts</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #4caf50' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>📘 Response Playbooks</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Execute predefined workflows for common incident types—malware, unauthorized access, data exfiltration, and more.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="success">Browse Playbooks</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #2196f3' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>🔗 SOAR Integration</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Connect Osrovnet to your Security Orchestration, Automation, and Response (SOAR) platform for automated containment and escalation.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="primary">Configure SOAR</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #ff9800' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>📂 Case Management</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Track incident lifecycle from detection to resolution. Assign roles, log actions, and generate audit-ready reports.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="warning">Manage Cases</Button>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}