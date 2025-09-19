import React from 'react';
import { Box, Typography, Grid, Paper } from '@mui/material';

export default function OverviewPage() {
  return (
    <Box>
      <Typography variant="h4" gutterBottom>Overview</Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6">System Health</Typography>
            <Typography variant="body2">Summary of system components and status.</Typography>
          </Paper>
        </Grid>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6">Recent Alerts</Typography>
            <Typography variant="body2">Latest alert activity and severity overview.</Typography>
          </Paper>
        </Grid>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6">Quick Stats</Typography>
            <Typography variant="body2">Performance indicators and KPIs.</Typography>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}
