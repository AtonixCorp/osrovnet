import React from 'react';
import { Box, Typography, Link } from '@mui/material';

export default function Footer() {
  return (
    <Box component="footer" sx={{ mt: 6, py: 3, textAlign: 'center', borderTop: '1px solid #eee' }}>
      <Typography variant="body2">© {new Date().getFullYear()} AtonixCorp — Osrovnet</Typography>
      <Typography variant="caption">Built for sovereignty and scale.</Typography>
    </Box>
  );
}
