import React, { useState, useEffect } from 'react';
import {
  Typography,
  TextField,
  Button,
  Paper,
  Divider,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  InputAdornment,
  IconButton,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody
} from '@mui/material';
import { Visibility, VisibilityOff } from '@mui/icons-material';

type ApiKey = {
  id: number;
  key: string;
  expires: string;
  created: string;
};

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000/api';
const TOKEN_KEY = 'osrovnet_token_v1';

export default function ApiKeyManager() {
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [expiration, setExpiration] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);

  useEffect(() => {
    // load existing keys from backend if available
    (async () => {
      try {
        const token = localStorage.getItem(TOKEN_KEY);
        if (!token) return;
        const res = await fetch(`${API_BASE}/keys/`, {
          headers: { Authorization: `Token ${token}` },
          credentials: 'include',
        });
        if (!res.ok) return;
        const data = await res.json();
        // expect array of {id,key,expires,created}
        setApiKeys(data);
      } catch (e) {
        // ignore - fallback to local state
      }
    })();
  }, []);

  const handleGenerateClick = () => {
    setDialogOpen(true);
  };

  const confirmGenerate = () => {
    if (!masterPassword || !expiration) return;
    const localKey: ApiKey = {
      id: Date.now(),
      key: `sk-${Math.random().toString(36).substring(2, 18)}`,
      expires: expiration,
      created: new Date().toISOString().split('T')[0],
    };

    // try to create on backend; if fails, keep localKey
    (async () => {
      try {
        const token = localStorage.getItem(TOKEN_KEY);
        if (token) {
          const res = await fetch(`${API_BASE}/keys/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Token ${token}` },
            credentials: 'include',
            body: JSON.stringify({ expires: expiration, master_password: masterPassword }),
          });
          if (res.ok) {
            const created = await res.json();
            // normalize response to ApiKey if possible
            const createdKey: ApiKey = {
              id: created.id ?? Date.now(),
              key: created.key ?? localKey.key,
              expires: created.expires ?? localKey.expires,
              created: created.created ?? localKey.created,
            };
            setApiKeys((prev) => [...prev, createdKey]);
            setMasterPassword('');
            setExpiration('');
            setDialogOpen(false);
            return;
          }
        }
      } catch (e) {
        // fallthrough to local key
      }

      // fallback: add localKey
      setApiKeys((prev) => [...prev, localKey]);
    setMasterPassword('');
    setExpiration('');
    setDialogOpen(false);
    })();
  };

  const revokeKey = (id: number) => {
    // attempt server delete then update local state
    (async () => {
      try {
        const token = localStorage.getItem(TOKEN_KEY);
        if (token) {
          await fetch(`${API_BASE}/keys/${id}/`, {
            method: 'DELETE',
            headers: { Authorization: `Token ${token}` },
            credentials: 'include',
          });
        }
      } catch (e) {
        // ignore
      }
      setApiKeys((prev) => prev.filter((k) => k.id !== id));
    })();
  };

  return (
    <Paper sx={{ p: 4, backgroundColor: '#f4f6f8' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: '#1a237e' }}>
        API Key Management
      </Typography>

      <Typography variant="body1" sx={{ mb: 3, color: '#555' }}>
        Generate secure API keys, set expiration dates, and revoke access as needed. Master password is required for key creation.
      </Typography>

      <Button variant="contained" onClick={handleGenerateClick} sx={{ mb: 3 }}>
        Generate New API Key
      </Button>

      <Divider sx={{ mb: 3 }} />

      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell><strong>Key</strong></TableCell>
            <TableCell><strong>Created</strong></TableCell>
            <TableCell><strong>Expires</strong></TableCell>
            <TableCell><strong>Actions</strong></TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {apiKeys.map((key) => (
            <TableRow key={key.id}>
              <TableCell>{key.key}</TableCell>
              <TableCell>{key.created}</TableCell>
              <TableCell>{key.expires}</TableCell>
              <TableCell>
                <Button variant="outlined" color="error" onClick={() => revokeKey(key.id)}>
                  Revoke
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {/* Master Password Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)}>
        <DialogTitle>🔐 Enter Master Password</DialogTitle>
        <DialogContent sx={{ display: 'grid', gap: 2, mt: 1 }}>
          <TextField
            label="Master Password"
            type={showPassword ? 'text' : 'password'}
            value={masterPassword}
            onChange={(e) => setMasterPassword(e.target.value)}
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton onClick={() => setShowPassword(!showPassword)} edge="end">
                    {showPassword ? <VisibilityOff /> : <Visibility />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
            required
          />
          <TextField
            label="Expiration Date"
            type="date"
            value={expiration}
            onChange={(e) => setExpiration(e.target.value)}
            InputLabelProps={{ shrink: true }}
            required
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={confirmGenerate}>Generate</Button>
        </DialogActions>
      </Dialog>
    </Paper>
  );
}