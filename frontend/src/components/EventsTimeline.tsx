import React, { useEffect, useState } from 'react';
import { Card, CardContent, Typography, List, ListItem, ListItemText, Chip } from '@mui/material';
import api from '../api/osrovnetApi';

const EventsTimeline: React.FC = () => {
  const [events, setEvents] = useState<any[]>([]);

  useEffect(() => {
    let mounted = true;
    const fetchEvents = async () => {
      try {
        const data = await api.Analytics.events('?limit=20');
        if (!mounted) return;
        setEvents(data.results || data || []);
      } catch (e) {
        console.error('fetchEvents error', e);
      }
    };
    fetchEvents();
    const interval = setInterval(fetchEvents, 10000);
    return () => { mounted = false; clearInterval(interval); };
  }, []);

  return (
    <Card>
      <CardContent>
        <Typography variant="h6">Events</Typography>
        <List>
          {events.map((ev) => (
            <ListItem key={ev.id}>
              <ListItemText
                primary={ev.event_type}
                secondary={<span>{new Date(ev.timestamp).toLocaleString()} • {ev.payload?.message || JSON.stringify(ev.payload)}</span>}
              />
              <Chip label={ev.severity || 'info'} size="small" />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default EventsTimeline;
