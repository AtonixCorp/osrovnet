import React, { useState } from 'react';
import { Box, Typography, Paper, TextField, Button, Grid } from '@mui/material';

export default function Home() {
  const [email, setEmail] = useState('');
  const [msg, setMsg] = useState('');

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    // For demo we'll store to localStorage as newsletter signups
    const key = 'osrovnet_newsletter';
    const raw = localStorage.getItem(key) || '[]';
    const arr = JSON.parse(raw);
    arr.push({ email, date: new Date().toISOString() });
    localStorage.setItem(key, JSON.stringify(arr));
    setMsg('Thanks! You are subscribed.');
    setEmail('');
  };

  return (
    <Box>
      <Paper sx={{ p: 4, mb: 3 }}>
        <Typography variant="h3" gutterBottom>Osrovnet – Network Security Platform</Typography>
        <Typography variant="subtitle1" gutterBottom>
          Osrovnet is AtonixCorp’s flagship solution for sovereign network defense, threat intelligence, and infrastructure resilience. Engineered for mission-critical environments and autonomous systems, Osrovnet empowers organizations to secure their digital perimeter with precision, insight, and operational control.
        </Typography>
        <Typography paragraph>
          Built from the ground up for environments where compromise is not an option, Osrovnet combines real-time telemetry, adaptive threat response, and modular infrastructure monitoring into a unified platform. Whether deployed in offshore data centers, enterprise networks, or high-risk operational zones, Osrovnet delivers clarity where others offer noise—and autonomy where others demand dependence.
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Typography variant="h6">Platform Capabilities</Typography>
            <Typography>🛡️ Network Security, 🎯 Threat Intelligence, 🏗️ Infrastructure Resilience</Typography>
          </Grid>
          <Grid item xs={12} md={6}>
            <form onSubmit={submit}>
              <Typography variant="h6">Subscribe to Newsletter</Typography>
              <TextField label="Email" value={email} onChange={(e) => setEmail(e.target.value)} fullWidth />
              <Button sx={{ mt: 1 }} type="submit" variant="contained">Subscribe</Button>
              <Typography variant="caption" display="block">{msg}</Typography>
            </form>
          </Grid>
        </Grid>
      </Paper>
    </Box>
  );
}
