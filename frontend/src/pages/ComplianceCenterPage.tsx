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

export default function ComplianceCenterPage() {
  return (
    <Box sx={{ p: 4, backgroundColor: '#f4f6f8', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: '#1a237e' }}>
        Compliance Center
      </Typography>

      <Typography variant="body1" sx={{ mb: 3, color: '#555' }}>
        Align your infrastructure with global standards. The Compliance Center helps you map findings to frameworks like NIST, ISO, and GDPR, maintain audit trails, and track remediation workflows with precision.
      </Typography>

      <Divider sx={{ mb: 3 }} />

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #4caf50' }}>
            <Typography variant="h6">📐 Standards Mapping</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Automatically correlate scan results and threat indicators with compliance frameworks. Supports NIST 800-53, ISO 27001, GDPR, and custom policies.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="success">View Mappings</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #2196f3' }}>
            <Typography variant="h6">📁 Audit Trail</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Maintain immutable logs of system activity, user actions, and scan results. Exportable for external auditors and internal reviews.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="primary">Access Logs</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #ff9800' }}>
            <Typography variant="h6">🔧 Remediation Tracking</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Assign, monitor, and verify remediation tasks linked to compliance gaps. Supports role-based workflows and deadline enforcement.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="warning">Track Remediation</Button>
          </Paper>
        </Grid>

        <Grid item xs={12}>
          <Paper elevation={2} sx={{ p: 3, borderLeft: '6px solid #9c27b0' }}>
            <Typography variant="h6">📝 Compliance Notes</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Add internal notes for auditors, legal teams, or executive summaries. Useful for documenting decisions, exceptions, or policy interpretations.
            </Typography>
            <TextField
              label="Add a note"
              multiline
              rows={4}
              fullWidth
              variant="outlined"
              sx={{ mt: 2 }}
              placeholder="e.g. This finding aligns with ISO 27001 control A.12.4.1 and has been remediated as of Sept 18..."
            />
            <Button variant="contained" sx={{ mt: 2 }} color="secondary">Save Note</Button>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}