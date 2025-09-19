import React, { useState } from 'react';
import {
  Box,
  TextField,
  Button,
  Paper,
  Typography,
  Link,
  Divider
} from '@mui/material';
import { useAuth } from '../auth/AuthProvider';

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await login(username, password);
    if (!res.ok) {
      setErr(res.error || 'Invalid credentials');
    } else {
      setErr('');
      window.location.hash = '#/';
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 4, maxWidth: 420, mx: 'auto', mt: 6 }}>
      <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
        Welcome Back
      </Typography>
      <Typography variant="body2" sx={{ mb: 2, color: '#666' }}>
        Enter your credentials to access the Osrovnet dashboard.
      </Typography>

      <Divider sx={{ mb: 3 }} />

      <Box component="form" onSubmit={submit} sx={{ display: 'grid', gap: 2 }}>
        <TextField
          label="Username or Email"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
        <TextField
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />

        <Button variant="contained" type="submit" sx={{ mt: 2 }}>
          Login
        </Button>

        {err && (
          <Typography variant="body2" color="error" sx={{ mt: 1 }}>
            {err}
          </Typography>
        )}

        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 2 }}>
          <Link href="#/forgot-password" variant="body2">
            Forgot password?
          </Link>
          <Link href="#/signup" variant="body2">
            Create account
          </Link>
        </Box>
      </Box>
    </Paper>
  );
}