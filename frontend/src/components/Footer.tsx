import React from 'react';
import {
  Box,
  Typography,
  Link,
  IconButton,
  TextField,
  Button,
  Stack,
  useTheme,
} from '@mui/material';
import GitHubIcon from '@mui/icons-material/GitHub';
import LinkedInIcon from '@mui/icons-material/LinkedIn';
import CodeIcon from '@mui/icons-material/Code';
import './Footer.css';

export default function Footer() {
  const theme = useTheme();
  const [email, setEmail] = React.useState('');
  const [subscribed, setSubscribed] = React.useState(false);

  const handleSubscribe = (e: React.FormEvent) => {
    e.preventDefault();
    // In a real app we'd POST to a newsletter API — for now simulate success
    if (email.includes('@')) {
      setSubscribed(true);
    }
  };

  return (
    <Box
      component="footer"
      sx={{
        mt: 6,
        py: 4,
        px: 2,
        borderTop: `1px solid ${theme.palette.divider}`,
        backgroundColor: theme.palette.background.paper,
      }}
    >
      <Box sx={{ maxWidth: 1100, mx: 'auto', display: 'flex', flexWrap: 'wrap', gap: 2, alignItems: 'center', justifyContent: 'space-between' }}>
        <Box>
          <Typography variant="h6">AtonixCorp</Typography>
          <Typography variant="caption">© {new Date().getFullYear()} — Osrovnet</Typography>
        </Box>

        <Stack direction="row" spacing={1} alignItems="center">
          <IconButton aria-label="GitHub" component={Link} href="https://github.com/atonixcorp" target="_blank" rel="noopener">
            <GitHubIcon />
          </IconButton>
          <IconButton aria-label="GitLab" component={Link} href="https://gitlab.com/atonixcorp" target="_blank" rel="noopener">
            <CodeIcon />
          </IconButton>
          <IconButton aria-label="LinkedIn" component={Link} href="https://www.linkedin.com/company/atonixcorp" target="_blank" rel="noopener">
            <LinkedInIcon />
          </IconButton>
        </Stack>

        <Box component="form" onSubmit={handleSubscribe} sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
          <TextField
            size="small"
            type="email"
            placeholder="Email for newsletter"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            aria-label="Newsletter email"
          />
          <Button type="submit" variant="contained" size="small">
            Subscribe
          </Button>
        </Box>
      </Box>

      <Box sx={{ mt: 2, textAlign: 'center' }}>
        {subscribed ? (
          <Typography variant="body2">Thanks for subscribing! You'll receive our updates shortly.</Typography>
        ) : (
          <Typography variant="caption">Built for sovereignty and scale. Contact: support@atonixcorp.com</Typography>
        )}
      </Box>
    </Box>
  );
}
