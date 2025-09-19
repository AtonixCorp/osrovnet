import React, { useState, useEffect } from 'react';
import {
  Box,
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
  // SSH key fields
  const [publicKey, setPublicKey] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [mode, setMode] = useState<'paste' | 'generate'>('paste');

  const handleSaveSsh = async () => {
    if (!publicKey && !privateKey) return;
    const localId = Date.now();
    const item = {
      id: localId,
      key: publicKey || privateKey || '',
      created: new Date().toISOString().split('T')[0],
      expires: '',
      type: publicKey ? 'public' : 'private',
    };

    try {
      const token = localStorage.getItem(TOKEN_KEY);
      if (token) {
        const res = await fetch(`${API_BASE}/ssh-keys/`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Token ${token}` },
          credentials: 'include',
          body: JSON.stringify({ public_key: publicKey, private_key: privateKey }),
        });
        if (res.ok) {
          const created = await res.json();
          setApiKeys((prev) => [...prev, { id: created.id ?? localId, key: created.public_key ?? item.key, created: created.created ?? item.created, expires: created.expires ?? item.expires }]);
          setPublicKey('');
          setPrivateKey('');
          return;
        }
      }
    } catch (e) {
      // ignore
    }

    // fallback local
    setApiKeys((prev) => [...prev, item]);
    setPublicKey('');
    setPrivateKey('');
  };

  // generate RSA keypair and export PEMs
  const generateKeyPair = async () => {
    try {
      const kp = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['sign', 'verify']
      );
      const priv = await window.crypto.subtle.exportKey('pkcs8', kp.privateKey);
      const pub = await window.crypto.subtle.exportKey('spki', kp.publicKey);

      const toBase64 = (buf: ArrayBuffer) => {
        const bytes = new Uint8Array(buf);
        let bin = '';
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return window.btoa(bin);
      };

      const wrapPem = (b64: string, label: string) => {
        const lines = b64.match(/.{1,64}/g) || [];
        return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
      };

      const privPem = wrapPem(toBase64(priv), 'PRIVATE KEY');
      const pubPem = wrapPem(toBase64(pub), 'PUBLIC KEY');

      setPrivateKey(privPem);
      setPublicKey(pubPem);
      setMode('paste');
    } catch (e) {
      console.error('Key generation failed', e);
    }
  };

  const confirmGenerate = () => {
    if (!masterPassword || !expiration) return;

    const localKey: ApiKey = {
      id: Date.now(),
      key: `sk-${Math.random().toString(36).substring(2, 18)}`,
      expires: expiration,
      created: new Date().toISOString().split('T')[0],
    };

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
        // fallback
      }
      setApiKeys((prev) => [...prev, localKey]);
      setMasterPassword('');
      setExpiration('');
      setDialogOpen(false);
    })();
  };

  const revokeKey = (id: number) => {
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

  useEffect(() => {
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
        setApiKeys(data);
      } catch (e) {
        // ignore
      }
    })();
  }, []);

  return (
    <Paper sx={{ p: 4, backgroundColor: '#f4f6f8' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: '#1a237e' }}>
        API Key Management
      </Typography>

      <Typography variant="body1" sx={{ mb: 3, color: '#555' }}>
        Generate secure API keys, set expiration dates, and revoke access as needed. Master password is required for key creation.
      </Typography>

      <Typography variant="h6" sx={{ mt: 2 }}>SSH Keys</Typography>
      <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mb: 1 }}>
        <Button variant={mode === 'paste' ? 'contained' : 'outlined'} onClick={() => setMode('paste')}>Paste</Button>
        <Button variant={mode === 'generate' ? 'contained' : 'outlined'} onClick={() => setMode('generate')}>Generate</Button>
        {mode === 'generate' && (
          <Button variant="outlined" onClick={generateKeyPair}>Generate Keys</Button>
        )}
      </Box>
      <Typography variant="body2" sx={{ mb: 1, color: '#666' }}>Paste your public and/or private SSH keys below and click Save.</Typography>
      <TextField
        label="Public Key"
        multiline
        minRows={2}
        fullWidth
        value={publicKey}
        onChange={(e) => setPublicKey(e.target.value)}
        sx={{ mb: 1 }}
      />
      <TextField
        label="Private Key"
        multiline
        minRows={2}
        fullWidth
        value={privateKey}
        onChange={(e) => setPrivateKey(e.target.value)}
        sx={{ mb: 1 }}
      />
      <Button variant="contained" onClick={handleSaveSsh} sx={{ mb: 3 }}>Save SSH Key</Button>

      <Divider sx={{ mb: 3 }} />

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