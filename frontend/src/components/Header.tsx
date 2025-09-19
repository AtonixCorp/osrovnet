import React from 'react';
import { AppBar, Toolbar, Typography, Button, Box } from '@mui/material';
import { useAuth } from '../auth/AuthProvider';

export default function Header() {
  const { user, logout } = useAuth();
  return (
    <AppBar position="static">
      <Toolbar sx={{ display: 'flex', justifyContent: 'space-between' }}>
        <Box>
          <Typography variant="h6">Osrovnet – Network Security Platform</Typography>
          <Typography variant="caption">AtonixCorp</Typography>
        </Box>
        <Box>
          {user ? (
            <>
              <Button color="inherit" href="#/">Home</Button>
              <Button color="inherit" onClick={() => logout()}>Logout</Button>
            </>
          ) : (
            <>
              <Button color="inherit" href="#/login">Login</Button>
              <Button color="inherit" href="#/signup">Sign up</Button>
            </>
          )}
        </Box>
      </Toolbar>
    </AppBar>
  );
}
