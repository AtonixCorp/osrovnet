import React, { useState } from 'react';
import { Box, TextField, Button, Paper, Typography } from '@mui/material';
import { useAuth } from '../auth/AuthProvider';

export default function Signup() {
  const { signup } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await signup(username, password);
    if (res.ok) {
      setMsg('Account created. Please log in.');
      setErr('');
      // redirect to login immediately; App's hash listener will render the Login page
      window.location.hash = '#/login';
    } else {
      setMsg('');
      setErr(res.error || 'Signup failed');
    }
  };

  return (
    <Paper sx={{ p: 3, maxWidth: 420 }}>
      <Typography variant="h5" gutterBottom>Sign up</Typography>
      <Box component="form" onSubmit={submit} sx={{ display: 'grid', gap: 2 }}>
        <TextField label="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <TextField label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <Button variant="contained" type="submit">Create account</Button>
        <Typography color="success.main">{msg}</Typography>
        <Typography color="error">{err}</Typography>
      </Box>
    </Paper>
  );
}
