import React from 'react';
import {
  Box,
  Typography,
  Grid,
  Paper,
  Button,
  Divider,
  TextField,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
} from '@mui/material';

export default function TelemetryLogsPage() {
  // Sample static logs (replace with live data)
  const logs = [
    { timestamp: '2025-09-19 10:42:01', source: '192.168.1.10', event: 'Port scan detected', severity: 'High' },
    { timestamp: '2025-09-19 10:41:22', source: '10.0.0.5', event: 'Packet drop anomaly', severity: 'Medium' },
    { timestamp: '2025-09-19 10:40:10', source: '172.16.0.2', event: 'Unauthorized access attempt', severity: 'Critical' },
  ];

  return (
    <Box sx={{ p: 4, backgroundColor: '#f4f6f8', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: '#1a237e' }}>
        Telemetry & Logs
      </Typography>

      <Typography variant="body1" sx={{ mb: 3, color: '#555' }}>
        Monitor real-time traffic, inspect packets, and review historical logs across all network zones. This module supports forensic analysis, anomaly detection, and exportable audit trails.
      </Typography>

      <Divider sx={{ mb: 3 }} />

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #2196f3' }}>
            <Typography variant="h6">🔍 Live Traffic Logs</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              View incoming/outgoing traffic in real time. Filter by IP, protocol, or severity.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="primary">Open Live Stream</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #4caf50' }}>
            <Typography variant="h6">🧪 Packet Inspection</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Inspect payloads, headers, and anomalies. Supports TCP, UDP, ICMP, and custom protocols.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="success">Launch Inspector</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #ff9800' }}>
            <Typography variant="h6">📅 Event Timeline</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Visualize log events chronologically. Useful for incident correlation and root cause analysis.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="warning">View Timeline</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #f44336' }}>
            <Typography variant="h6">📁 Historical Search</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Search logs by date, source, or event type. Export results for compliance or audit.
            </Typography>
            <TextField
              label="Search logs"
              variant="outlined"
              fullWidth
              sx={{ mt: 2 }}
              placeholder="e.g. 192.168.1.10 or 'access attempt'"
            />
            <Button variant="contained" sx={{ mt: 2 }} color="error">Search & Export</Button>
          </Paper>
        </Grid>
      </Grid>

      <Divider sx={{ my: 4 }} />
      <Typography variant="h6" gutterBottom>📋 Recent Events</Typography>
      <Paper elevation={2} sx={{ p: 2 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell><strong>Timestamp</strong></TableCell>
              <TableCell><strong>Source</strong></TableCell>
              <TableCell><strong>Event</strong></TableCell>
              <TableCell><strong>Severity</strong></TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {logs.map((log, index) => (
              <TableRow key={index}>
                <TableCell>{log.timestamp}</TableCell>
                <TableCell>{log.source}</TableCell>
                <TableCell>{log.event}</TableCell>
                <TableCell>{log.severity}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Paper>
    </Box>
  );
}