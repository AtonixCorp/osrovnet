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
  const [totpSecret, setTotpSecret] = useState<string>('');
  const [totpCode, setTotpCode] = useState<string>('');
  const [totpError, setTotpError] = useState<string>('');

  useEffect(() => {
    setSettings(loadSettings());
    // load any persisted TOTP secret
    try {
      const s = localStorage.getItem('osrovnet_totp_secret');
      if (s) setTotpSecret(s);
    } catch (e) {}
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

  // --- TOTP helpers ---
  function generateBase32Secret(length = 16) {
    // RFC4648 Base32 alphabet
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += alphabet[bytes[i] % alphabet.length];
    return s;
  }

  function base32ToBytes(base32: string) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = base32.replace(/=+$/,'').toUpperCase().replace(/[^A-Z2-7]/g, '');
    const bits: number[] = [];
    for (let i = 0; i < clean.length; i++) {
      const val = alphabet.indexOf(clean[i]);
      for (let b = 4; b >= 0; b--) bits.push((val >> b) & 1);
    }
    const bytes: number[] = [];
    for (let i = 0; i + 7 < bits.length; i += 8) {
      let byte = 0;
      for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
      bytes.push(byte);
    }
    return new Uint8Array(bytes).buffer;
  }

  async function generateTotp(secret: string, digits = 6, step = 30) {
    const keyBuf = base32ToBytes(secret);
    const key = await crypto.subtle.importKey('raw', keyBuf, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / step);
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    // big-endian
    view.setUint32(4, counter & 0xffffffff);
    view.setUint32(0, Math.floor(counter / 0x100000000));
    const sig = await crypto.subtle.sign('HMAC', key, buf);
    const sigBytes = new Uint8Array(sig);
    const offset = sigBytes[sigBytes.length - 1] & 0x0f;
    const code = ((sigBytes[offset] & 0x7f) << 24) | ((sigBytes[offset+1] & 0xff) << 16) | ((sigBytes[offset+2] & 0xff) << 8) | (sigBytes[offset+3] & 0xff);
    const str = String(code % 10 ** digits).padStart(digits, '0');
    return str;
  }

  const handleVerifyAndSave = async () => {
    setTotpError('');
    if (!totpSecret) { setTotpError('No TOTP secret'); return; }
    try {
      const expected = await generateTotp(totpSecret);
      if (totpCode.trim() === expected) {
        // mark settings enabled and persist
        const next = { ...settings, enable2FA: true };
        setSettings(next);
        handleSave();
        // try to register with backend (placeholder) — implement backend endpoint /2fa/enable/ if desired
        try {
          const token = localStorage.getItem('osrovnet_token_v1');
          if (token) {
            await fetch((process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000/api') + '/2fa/enable/', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', Authorization: `Token ${token}` },
              credentials: 'include',
              body: JSON.stringify({ secret: totpSecret }),
            });
          }
        } catch (e) {}
        setSavedMessage('2FA enabled');
        setTimeout(() => setSavedMessage(''), 2000);
      } else {
        setTotpError('Code did not match. Check your authenticator app and retry.');
      }
    } catch (e) {
      setTotpError('Verification failed');
    }
  };

  const handleDisable2FA = async () => {
    const next = { ...settings, enable2FA: false };
    setSettings(next);
    handleSave();
    try { localStorage.removeItem('osrovnet_totp_secret'); } catch (e) {}
    try {
      const token = localStorage.getItem('osrovnet_token_v1');
      if (token) {
        await fetch((process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000/api') + '/2fa/disable/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Token ${token}` },
          credentials: 'include',
        });
      }
    } catch (e) {}
    setSavedMessage('2FA disabled');
    setTimeout(() => setSavedMessage(''), 2000);
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
        {/* TOTP setup */}
        <Box>
          {!settings.enable2FA ? (
            <>
              <Typography variant="body2" sx={{ mb: 1 }}>Set up 2FA using an authenticator app (TOTP). Click Generate to create a secret and scan the QR code.</Typography>
              <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                <Button onClick={() => { const s = generateBase32Secret(20); setTotpSecret(s); try { localStorage.setItem('osrovnet_totp_secret', s); } catch (e) {} }}>Generate Secret</Button>
                <Button onClick={() => { navigator.clipboard?.writeText(totpSecret || ''); }}>Copy Secret</Button>
              </Box>
              {totpSecret && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="body2">Secret: <code>{totpSecret}</code></Typography>
                  <Typography variant="body2" sx={{ mt: 1 }}>QR (scan with Google Authenticator / Authy):</Typography>
                  <Box sx={{ mt: 1 }}>
                    <img alt="TOTP QR" src={`https://chart.googleapis.com/chart?cht=qr&chs=200x200&chl=${encodeURIComponent(`otpauth://totp/Osrovnet:${settings.email || 'user'}?secret=${totpSecret}&issuer=Osrovnet`)}`} />
                  </Box>
                  <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                    <TextField label="Enter code from app" value={totpCode} onChange={(e) => setTotpCode(e.target.value)} />
                    <Button variant="contained" onClick={handleVerifyAndSave}>Verify & Enable</Button>
                  </Box>
                  {totpError && <Typography color="error" sx={{ mt: 1 }}>{totpError}</Typography>}
                </Box>
              )}
            </>
          ) : (
            <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
              <Typography variant="body2">2FA is enabled. You can disable it below.</Typography>
              <Button variant="outlined" color="error" onClick={handleDisable2FA}>Disable 2FA</Button>
            </Box>
          )}
        </Box>
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