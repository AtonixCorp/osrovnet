import React, { useEffect, useState } from 'react';
import { Card, CardContent, Typography, List, ListItem, ListItemText, Button } from '@mui/material';
import api from '../api/osrovnetApi';

const ScheduledReportsManager: React.FC = () => {
  const [schedules, setSchedules] = useState<any[]>([]);

  useEffect(() => {
    let mounted = true;
    const fetchSchedules = async () => {
      try {
        const data = await api.Analytics.scheduledReports();
        if (!mounted) return;
        setSchedules(data.results || data || []);
      } catch (e) {
        console.error('fetchSchedules error', e);
      }
    };
    fetchSchedules();
    const interval = setInterval(fetchSchedules, 15000);
    return () => { mounted = false; clearInterval(interval); };
  }, []);

  const runNow = async (id: number) => {
    try {
      await api.request(`/analytics/scheduled-reports/${id}/run_now/`, { method: 'POST' });
      alert('Triggered');
    } catch (e) {
      console.error('runNow error', e);
      alert('Failed to trigger');
    }
  };

  return (
    <Card>
      <CardContent>
        <Typography variant="h6">Scheduled Reports</Typography>
        <List>
          {schedules.map((s) => (
            <ListItem key={s.id} secondaryAction={<Button onClick={() => runNow(s.id)}>Run Now</Button>}>
              <ListItemText primary={s.report?.name || 'Report'} secondary={`cron: ${s.cron} • enabled: ${s.enabled}`} />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default ScheduledReportsManager;
