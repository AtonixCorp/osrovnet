import React from 'react';
import { Box, Typography, Grid, Paper } from '@mui/material';

export default function OverviewPage() {
  return (
    <Box sx={{ p: 4, backgroundColor: '#f4f6f8', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: '#1a237e' }}>
        Overview
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #4caf50' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>System Health</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#555' }}>
              Summary of system components and status.
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} md={4}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #f44336' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>Recent Alerts</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#555' }}>
              Latest alert activity and severity overview.
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} md={4}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #2196f3' }}>
            <Typography variant="h6" sx={{ fontWeight: 500 }}>Quick Stats</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#555' }}>
              Performance indicators and KPIs.
            </Typography>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}