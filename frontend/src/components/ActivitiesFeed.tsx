import React, { useEffect, useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  List,
  ListItem,
  ListItemAvatar,
  Avatar,
  ListItemText,
  Chip,
  Box,
  CircularProgress,
  Divider
} from '@mui/material';
import {
  NotificationsActive,
  WarningAmber,
  BugReport,
  Cloud,
  Security
} from '@mui/icons-material';

import api from '../api/osrovnetApi';

interface Activity {
  id: number;
  timestamp: string;
  title: string;
  description?: string;
  source?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  type?: 'alert' | 'scan' | 'intel' | 'system' | 'other';
}

const iconForType = (type?: string) => {
  switch (type) {
    case 'alert':
      return <WarningAmber />;
    case 'scan':
      return <Cloud />;
    case 'intel':
      return <BugReport />;
    case 'system':
      return <NotificationsActive />;
    default:
      return <Security />;
  }
};

const colorForSeverity = (sev?: string) => {
  switch (sev) {
    case 'critical':
      return 'error';
    case 'high':
      return 'warning';
    case 'medium':
      return 'info';
    case 'low':
      return 'success';
    default:
      return 'default';
  }
};

const MOCK_ACTIVITIES: Activity[] = [
  {
    id: 1,
    timestamp: new Date().toISOString(),
    title: 'Critical alert: Suspicious inbound traffic',
    description: 'High volume of connections from 203.0.113.45 to multiple hosts.',
    source: 'IDS Sensor 3',
    severity: 'critical',
    type: 'alert'
  },
  {
    id: 2,
    timestamp: new Date(Date.now() - 1000 * 60 * 10).toISOString(),
    title: 'Scheduled scan completed',
    description: 'Comprehensive scan completed for 10.0.0.0/24',
    source: 'Nmap Scanner',
    severity: 'medium',
    type: 'scan'
  },
  {
    id: 3,
    timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    title: 'New IOC imported',
    description: '3 new indicators from TAXII feed matched internal assets.',
    source: 'Threat Intel',
    severity: 'high',
    type: 'intel'
  },
  {
    id: 4,
    timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    title: 'System: Redis restarted',
    description: 'Redis service restarted on host infra-redis-1',
    source: 'System',
    severity: 'low',
    type: 'system'
  }
];

const ActivitiesFeed: React.FC = () => {
  const [activities, setActivities] = useState<Activity[] | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;

    const fetchActivities = async () => {
      try {
        setLoading(true);
        const data = await api.Analytics.events('?limit=20');
        if (!mounted) return;
        const items = data.results || data || [];
        setActivities(items.length ? items : MOCK_ACTIVITIES);
      } catch (err) {
        setActivities(MOCK_ACTIVITIES);
        console.error('Failed to fetch activities:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    };

    fetchActivities();
    const interval = setInterval(fetchActivities, 30000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <Card>
      <CardContent>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Typography variant="h6">Activities</Typography>
          <Typography variant="caption" color="text.secondary">Live</Typography>
        </Box>

        {loading && !activities ? (
          <Box display="flex" alignItems="center" justifyContent="center" minHeight={120}>
            <CircularProgress size={24} />
            <Typography sx={{ ml: 2 }} variant="body2">Loading activities...</Typography>
          </Box>
        ) : (
          <List sx={{ maxHeight: 420, overflow: 'auto' }}>
            {activities && activities.length > 0 ? (
              activities.map((act) => (
                <React.Fragment key={act.id}>
                  <ListItem alignItems="flex-start">
                    <ListItemAvatar>
                      <Avatar sx={{ bgcolor: (theme) => theme.palette.grey[100], color: (theme) => theme.palette.text.primary }}>
                        {iconForType(act.type)}
                      </Avatar>
                    </ListItemAvatar>
                    <ListItemText
                      primary={
                        <Box display="flex" alignItems="center" justifyContent="space-between">
                          <Typography variant="subtitle2">{act.title}</Typography>
                          <Chip label={act.severity} color={colorForSeverity(act.severity) as any} size="small" />
                        </Box>
                      }
                      secondary={
                        <Box>
                          <Typography variant="caption" color="text.secondary">{new Date(act.timestamp).toLocaleString()} • {act.source}</Typography>
                          {act.description && (
                            <Typography variant="body2" color="text.secondary">{act.description}</Typography>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                  <Divider component="li" />
                </React.Fragment>
              ))
            ) : (
              <Typography color="text.secondary" align="center" sx={{ mt: 2 }}>No recent activities.</Typography>
            )}
          </List>
        )}
      </CardContent>
    </Card>
  );
};

export default ActivitiesFeed;
