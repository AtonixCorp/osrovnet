import React from 'react';
import { Box, Typography } from '@mui/material';
import './TerminalPage.css';
import { useAuth } from '../auth/AuthProvider';

const DEFAULT_TERMINAL = process.env.REACT_APP_TERMINAL_URL || 'http://localhost:7681';

export default function TerminalPage() {
  const { user } = useAuth();

  if (!user) {
    return (
      <Box>
        <Typography variant="h5">Unauthorized</Typography>
        <Typography variant="body1">You must be logged in to access the terminal.</Typography>
      </Box>
    );
  }

  return (
    <Box className="terminal-container">
      <Typography variant="h5" gutterBottom>
        Remote Terminal
      </Typography>
      <div className="terminal-embed-wrap">
        <iframe
          title="osrovnet-terminal"
          src={DEFAULT_TERMINAL}
          className="terminal-iframe"
          sandbox="allow-same-origin allow-scripts allow-forms allow-popups"
        />
      </div>
    </Box>
  );
}
