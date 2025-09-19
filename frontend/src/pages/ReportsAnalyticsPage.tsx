import React, { useState } from 'react';
import {
  Box,
  Typography,
  Grid,
  Paper,
  Button,
  Divider,
  TextField,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions
} from '@mui/material';

export default function ReportsAnalyticsPage() {
  const [format, setFormat] = useState<string>('json');
  const [since, setSince] = useState<string>('');
  const [until, setUntil] = useState<string>('');
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewData, setPreviewData] = useState<any>(null);

  const handleGenerate = async () => {
    try {
      const params = new URLSearchParams();
      params.set('format', format);
      if (since) params.set('since', since);
      if (until) params.set('until', until);

      const url = `/api/analytics/reports/generate/?${params.toString()}`;
      if (format === 'csv') {
        const resp = await fetch(url, { credentials: 'include' });
        const blob = await resp.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'osrovnet-report.csv';
        a.click();
        URL.revokeObjectURL(a.href);
        return;
      }

      const resp = await fetch(url, { credentials: 'include' });
      const data = await resp.json();
      setPreviewData(data);
      setPreviewOpen(true);
    } catch (e) {
      console.error('generate report error', e);
      alert('Failed to generate report');
    }
  };

  return (
    <Box sx={{ p: 4, backgroundColor: '#f4f6f8', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: '#1a237e' }}>
        Reports & Analytics
      </Typography>

      <Typography variant="body1" sx={{ mb: 3, color: '#555' }}>
        Generate detailed reports, export operational data, and schedule recurring analytics to support compliance, audits, and strategic decision-making.
      </Typography>

      <Divider sx={{ mb: 3 }} />

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #4caf50' }}>
            <Typography variant="h6">📊 Generate Reports</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Create on-demand reports for scan results, threat activity, and system health. Choose formats like PDF, CSV, or JSON.
            </Typography>
            <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mt: 2 }}>
              <FormControl size="small">
                <InputLabel id="format-label">Format</InputLabel>
                <Select
                  labelId="format-label"
                  value={format}
                  label="Format"
                  onChange={(e) => setFormat(e.target.value)}
                  sx={{ width: 120 }}
                >
                  <MenuItem value="json">JSON</MenuItem>
                  <MenuItem value="csv">CSV</MenuItem>
                </Select>
              </FormControl>
              <TextField
                label="Since"
                type="datetime-local"
                size="small"
                InputLabelProps={{ shrink: true }}
                value={since}
                onChange={(e) => setSince(e.target.value)}
              />
              <TextField
                label="Until"
                type="datetime-local"
                size="small"
                InputLabelProps={{ shrink: true }}
                value={until}
                onChange={(e) => setUntil(e.target.value)}
              />
              <Button variant="contained" sx={{ mt: 0 }} color="success" onClick={handleGenerate}>Generate</Button>
            </Box>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #2196f3' }}>
            <Typography variant="h6">📁 Export Data</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Export telemetry, alerts, and historical logs for external analysis or compliance review.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="primary">Export</Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, borderLeft: '6px solid #ff9800' }}>
            <Typography variant="h6">⏰ Schedule Reporting</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Automate report generation on a daily, weekly, or monthly basis. Configure delivery via email or secure endpoint.
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }} color="warning">Schedule</Button>
          </Paper>
        </Grid>

        <Grid item xs={12}>
          <Paper elevation={2} sx={{ p: 3, borderLeft: '6px solid #9c27b0' }}>
            <Typography variant="h6">📝 Analyst Notes</Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#666' }}>
              Add contextual notes to reports for internal review, executive summaries, or audit annotations.
            </Typography>
            <TextField
              label="Add a note"
              multiline
              rows={4}
              fullWidth
              variant="outlined"
              sx={{ mt: 2 }}
              placeholder="e.g. This report highlights a spike in unauthorized access attempts from external zones..."
            />
            <Button variant="contained" sx={{ mt: 2 }} color="secondary">Save Note</Button>
          </Paper>
        </Grid>
      </Grid>

        <Dialog open={previewOpen} fullWidth maxWidth="lg" onClose={() => setPreviewOpen(false)}>
          <DialogTitle>Report Preview (JSON)</DialogTitle>
          <DialogContent>
            <pre style={{ maxHeight: '60vh', overflow: 'auto' }}>{previewData ? JSON.stringify(previewData, null, 2) : 'No data'}</pre>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setPreviewOpen(false)}>Close</Button>
          </DialogActions>
        </Dialog>
    </Box>
  );
}