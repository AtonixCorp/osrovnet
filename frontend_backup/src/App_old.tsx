import React from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Container,
  Grid,
  Card,
  CardContent,
  Box,
  CssBaseline,
  ThemeProvider,
  createTheme,
} from '@mui/material';
import {
  Security,
  NetworkCheck,
  TrendingUp,
  Warning,
} from '@mui/icons-material';
import './App.css';

// Dark theme for cybersecurity aesthetic
const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00ff41', // Matrix green
    },
    secondary: {
      main: '#ff4444', // Alert red
    },
    background: {
      default: '#0a0a0a',
      paper: '#1a1a1a',
    },
  },
  typography: {
    fontFamily: '"Roboto Mono", "Courier New", monospace',
  },
});

const StatCard: React.FC<{
  title: string;
  value: string;
  icon: React.ReactNode;
  color: string;
}> = ({ title, value, icon, color }) => (
  <Card sx={{ height: '100%', bgcolor: 'background.paper' }}>
    <CardContent>
      <Box display="flex" alignItems="center" justifyContent="space-between">
        <Box>
          <Typography variant="h6" component="div" gutterBottom>
            {title}
          </Typography>
          <Typography variant="h4" component="div" sx={{ color }}>
            {value}
          </Typography>
        </Box>
        <Box sx={{ color }}>{icon}</Box>
      </Box>
    </CardContent>
  </Card>
);

function App() {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Box sx={{ flexGrow: 1 }}>
        <AppBar position="static" sx={{ bgcolor: 'background.paper' }}>
          <Toolbar>
            <Security sx={{ mr: 2, color: 'primary.main' }} />
            <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
              Osrovnet - Network Security Platform
            </Typography>
            <Typography variant="subtitle1" sx={{ color: 'text.secondary' }}>
              AtonixCorp
            </Typography>
          </Toolbar>
        </AppBar>

        <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
          <Typography variant="h4" gutterBottom sx={{ color: 'primary.main' }}>
            Network Security Dashboard
          </Typography>
          <Typography variant="subtitle1" gutterBottom sx={{ mb: 4 }}>
            Advanced threat intelligence and resilient infrastructure monitoring
          </Typography>

          <Grid container spacing={3}>
            {/* Statistics Cards */}
            <Grid xs={12} sm={6} md={3}>
              <StatCard
                title="Network Status"
                value="SECURE"
                icon={<NetworkCheck sx={{ fontSize: 40 }} />}
                color="#00ff41"
              />
            </Grid>
            <Grid xs={12} sm={6} md={3}>
              <StatCard
                title="Active Threats"
                value="3"
                icon={<Warning sx={{ fontSize: 40 }} />}
                color="#ff4444"
              />
            </Grid>
            <Grid xs={12} sm={6} md={3}>
              <StatCard
                title="Security Score"
                value="94%"
                icon={<Security sx={{ fontSize: 40 }} />}
                color="#00ff41"
              />
            </Grid>
            <Grid xs={12} sm={6} md={3}>
              <StatCard
                title="Uptime"
                value="99.9%"
                icon={<TrendingUp sx={{ fontSize: 40 }} />}
                color="#00ff41"
              />
            </Grid>

            {/* Main Dashboard Content */}
            <Grid xs={12} md={8}>
              <Card sx={{ height: 400, bgcolor: 'background.paper' }}>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Network Traffic Analysis
                  </Typography>
                  <Box
                    sx={{
                      height: 300,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      border: '1px dashed',
                      borderColor: 'primary.main',
                      borderRadius: 1,
                    }}
                  >
                    <Typography variant="h6" sx={{ color: 'text.secondary' }}>
                      Real-time Network Monitoring
                      <br />
                      Coming Soon...
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid xs={12} md={4}>
              <Card sx={{ height: 400, bgcolor: 'background.paper' }}>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Threat Intelligence Feed
                  </Typography>
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="body2" sx={{ mb: 1 }}>
                      • Suspicious IP detected: 192.168.1.100
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 1 }}>
                      • Port scan attempt blocked
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 1 }}>
                      • Malware signature updated
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 1 }}>
                      • Firewall rules optimized
                    </Typography>
                    <Typography variant="body2" sx={{ color: 'primary.main' }}>
                      • System integrity verified ✓
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Container>
      </Box>
    </ThemeProvider>
  );
}

export default App;
