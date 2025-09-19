import React from 'react';
import { Box, Typography, Grid, Paper, Button } from '@mui/material';

export default function ScanEnginePage() {
  return (
    <Box sx={{ p: 4, backgroundColor: '#f4f6f8', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: '#1a237e' }}>
        Scan Engine
      </Typography>

      <Typography variant="body1" sx={{ mb: 3, color: '#555' }}>
        Launch scans, view history, and configure parameters. The Scan Engine module provides deep visibility into your network by performing targeted assessments across assets, ports, and protocols.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #4caf50' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>Quick Scan</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Perform lightweight scans for rapid asset discovery and basic port checks.
            </Typography>
            <Button variant="contained" sx={{ mt: 2 }} color="success">Start Quick Scan</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #2196f3' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>Deep Scan</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Run comprehensive scans with service fingerprinting, OS detection, and vulnerability mapping.
            </Typography>
            <Button variant="contained" sx={{ mt: 2 }} color="primary">Start Deep Scan</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #ff9800' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>Scan History</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Review previous scan results, compare changes, and export reports.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="warning">View History</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #f44336' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>Scan Configuration</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Customize scan parameters, schedule recurring scans, and assign profiles to targets.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="error">Configure</Button>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}