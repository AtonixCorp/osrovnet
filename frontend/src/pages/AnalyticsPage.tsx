import React from 'react';
import { Grid, Typography, Box } from '@mui/material';
import MetricWidget from '../components/MetricWidget';
import EventsTimeline from '../components/EventsTimeline';
import ReportBuilder from '../components/ReportBuilder';
import ScheduledReportsManager from '../components/ScheduledReportsManager';

const AnalyticsPage: React.FC = () => {
  return (
    <Box sx={{ p: 1 }}>
      <Typography variant="h4" gutterBottom>Analytics</Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} md={8}>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <MetricWidget metricName="system_cpu" title="CPU Usage" />
            </Grid>
            <Grid item xs={12} md={6}>
              <MetricWidget metricName="system_memory" title="Memory Usage" />
            </Grid>
            <Grid item xs={12}>
              <EventsTimeline />
            </Grid>
          </Grid>
        </Grid>
        <Grid item xs={12} md={4}>
          <ReportBuilder />
          <Box sx={{ mt: 2 }}>
            <ScheduledReportsManager />
          </Box>
        </Grid>
      </Grid>
    </Box>
  );
};

export default AnalyticsPage;
