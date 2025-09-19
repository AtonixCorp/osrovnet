import React from 'react';
import { Box, Typography, Paper, Grid } from '@mui/material';

export default function NetworkTargetsPage() {
  return (
    <Box sx={{ p: 4, backgroundColor: '#f4f6f8', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: '#1a237e' }}>
        Network Targets
      </Typography>

      <Typography variant="body1" sx={{ mb: 3, color: '#555' }}>
        Manage monitored assets, groups, profiles, and trust zones. This module allows you to classify
        network targets by function, risk level, and operational priority.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #4caf50' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>Asset Groups</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Organize targets by function—servers, endpoints, IoT, cloud instances.
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #2196f3' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>Scan Profiles</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Assign quick or deep scan configurations based on asset criticality.
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #ff9800' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>Trust Zones</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Define internal, DMZ, and external zones for policy enforcement.
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #f44336' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>Target Discovery</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Enable auto-discovery or manual entry of monitored assets.
            </Typography>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}