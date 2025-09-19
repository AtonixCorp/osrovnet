import React, { useState } from 'react';
import { Box, TextField, Button, Paper, Typography } from '@mui/material';
import { useAuth } from '../auth/AuthProvider';

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await login(username, password);
    if (!res.ok) setErr(res.error || 'Invalid credentials');
    else {
      // navigate to dashboard root and update UI in-place
      window.location.hash = '#/';
      // no full reload; rely on AuthProvider state change to show dashboard
    }
  };

  return (
    <Paper sx={{ p: 3, maxWidth: 420 }}>
      <Typography variant="h5" gutterBottom>Login</Typography>
      <Box component="form" onSubmit={submit} sx={{ display: 'grid', gap: 2 }}>
        <TextField label="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <TextField label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <Button variant="contained" type="submit">Login</Button>
        <Typography color="error">{err}</Typography>
      </Box>
    </Paper>
  );
}
