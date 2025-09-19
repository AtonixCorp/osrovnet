import React, { useEffect, useState } from 'react';
import {
  Box,
  TextField,
  Button,
  Typography,
  Paper,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Divider,
  Switch,
  FormControlLabel
} from '@mui/material';

const STORAGE_KEY = 'osrovnet_settings_v1';

type Settings = {
  grafanaUrl: string;
  monitoringInterval: number;
  alertThreshold: 'low' | 'medium' | 'high';
  email: string;
  password: string;
  enable2FA: boolean;
  sessionTimeout: number;
  emailNotifications: boolean;
};

const defaultSettings: Settings = {
  grafanaUrl: '',
  monitoringInterval: 30,
  alertThreshold: 'medium',
  email: '',
  password: '',
  enable2FA: false,
  sessionTimeout: 15,
  emailNotifications: true,
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
    <Paper sx={{ p: 4, backgroundColor: '#f4f6f8' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: '#1a237e' }}>
        Settings
      </Typography>

      <Divider sx={{ my: 3 }} />
      <Typography variant="h6" gutterBottom>👤 Account Settings</Typography>
      <Box sx={{ display: 'grid', gap: 2, maxWidth: 640 }}>
        <TextField
          label="Email Address"
          type="email"
          value={settings.email}
          onChange={(e) => setSettings({ ...settings, email: e.target.value })}
        />
        <TextField
          label="New Password"
          type="password"
          value={settings.password}
          onChange={(e) => setSettings({ ...settings, password: e.target.value })}
          helperText="Leave blank to keep current password"
        />
      </Box>

      <Divider sx={{ my: 3 }} />
      <Typography variant="h6" gutterBottom>⚙️ System Preferences</Typography>
      <Box sx={{ display: 'grid', gap: 2, maxWidth: 640 }}>
        <TextField
          label="Grafana URL"
          value={settings.grafanaUrl}
          onChange={(e) => setSettings({ ...settings, grafanaUrl: e.target.value })}
          helperText="Optional: base URL for Grafana embedding"
        />
        <TextField
          label="Monitoring Interval (seconds)"
          type="number"
          value={String(settings.monitoringInterval)}
          onChange={(e) =>
            setSettings({
              ...settings,
              monitoringInterval: Math.max(5, Number(e.target.value) || 5),
            })
          }
        />
        <FormControl>
          <InputLabel id="alert-threshold-label">Alert Threshold</InputLabel>
          <Select
            labelId="alert-threshold-label"
            value={settings.alertThreshold}
            label="Alert Threshold"
            onChange={(e) =>
              setSettings({
                ...settings,
                alertThreshold: e.target.value as Settings['alertThreshold'],
              })
            }
          >
            <MenuItem value="low">Low</MenuItem>
            <MenuItem value="medium">Medium</MenuItem>
            <MenuItem value="high">High</MenuItem>
          </Select>
        </FormControl>
      </Box>

      <Divider sx={{ my: 3 }} />
      <Typography variant="h6" gutterBottom>📬 Notification Settings</Typography>
      <Box sx={{ display: 'grid', gap: 2, maxWidth: 640 }}>
        <FormControlLabel
          control={
            <Switch
              checked={settings.emailNotifications}
              onChange={(e) =>
                setSettings({ ...settings, emailNotifications: e.target.checked })
              }
            />
          }
          label="Enable Email Notifications"
        />
      </Box>

      <Divider sx={{ my: 3 }} />
      <Typography variant="h6" gutterBottom>🔐 Security Controls</Typography>
      <Box sx={{ display: 'grid', gap: 2, maxWidth: 640 }}>
        <FormControlLabel
          control={
            <Switch
              checked={settings.enable2FA}
              onChange={(e) =>
                setSettings({ ...settings, enable2FA: e.target.checked })
              }
            />
          }
          label="Enable Two-Factor Authentication (2FA)"
        />
        <TextField
          label="Session Timeout (minutes)"
          type="number"
          value={String(settings.sessionTimeout)}
          onChange={(e) =>
            setSettings({
              ...settings,
              sessionTimeout: Math.max(5, Number(e.target.value) || 5),
            })
          }
        />
      </Box>

      <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mt: 4 }}>
        <Button variant="contained" onClick={handleSave}>Save Settings</Button>
        <Button variant="outlined" onClick={() => setSettings(defaultSettings)}>Reset</Button>
        <Typography variant="body2" color="text.secondary">{savedMessage}</Typography>
      </Box>
    </Paper>
  );
}