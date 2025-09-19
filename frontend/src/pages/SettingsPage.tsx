import React, { useEffect, useState } from 'react';
import { Box, TextField, Button, Typography, Paper, FormControl, InputLabel, Select, MenuItem } from '@mui/material';

const STORAGE_KEY = 'osrovnet_settings_v1';

type Settings = {
  grafanaUrl: string;
  monitoringInterval: number; // seconds
  alertThreshold: 'low' | 'medium' | 'high';
};

const defaultSettings: Settings = {
  grafanaUrl: '',
  monitoringInterval: 30,
  alertThreshold: 'medium',
};

function loadSettings(): Settings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaultSettings;
    return { ...defaultSettings, ...JSON.parse(raw) };
  } catch (e) {
    return defaultSettings;
  }
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings>(defaultSettings);
  const [savedMessage, setSavedMessage] = useState<string>('');

  useEffect(() => {
    setSettings(loadSettings());
  }, []);

  const handleSave = () => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
      setSavedMessage('Settings saved');
      setTimeout(() => setSavedMessage(''), 2000);
    } catch (e) {
      setSavedMessage('Failed to save');
    }
  };

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>Settings</Typography>
      <Box component="form" sx={{ display: 'grid', gap: 2, maxWidth: 640 }}>
        <TextField
          label="Grafana URL"
          value={settings.grafanaUrl}
          onChange={(e) => setSettings({ ...settings, grafanaUrl: e.target.value })}
          helperText="Optional: base URL for Grafana embedding (e.g., https://grafana.example.com)"
        />

        <TextField
          label="Monitoring interval (seconds)"
          type="number"
          value={String(settings.monitoringInterval)}
          onChange={(e) => setSettings({ ...settings, monitoringInterval: Math.max(5, Number(e.target.value) || 5) })}
        />

        <FormControl>
          <InputLabel id="alert-threshold-label">Alert threshold</InputLabel>
          <Select
            labelId="alert-threshold-label"
            value={settings.alertThreshold}
            label="Alert threshold"
            onChange={(e) => setSettings({ ...settings, alertThreshold: e.target.value as Settings['alertThreshold'] })}
          >
            <MenuItem value="low">Low</MenuItem>
            <MenuItem value="medium">Medium</MenuItem>
            <MenuItem value="high">High</MenuItem>
          </Select>
        </FormControl>

        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <Button variant="contained" onClick={handleSave}>Save</Button>
          <Button variant="outlined" onClick={() => setSettings(defaultSettings)}>Reset</Button>
          <Typography variant="body2" color="text.secondary">{savedMessage}</Typography>
        </Box>
      </Box>
    </Paper>
  );
}
