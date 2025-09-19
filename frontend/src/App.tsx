import React, { useState } from 'react';
import {
  ThemeProvider,
  createTheme,
  CssBaseline,
  AppBar,
  Toolbar,
  Typography,
  Box,
  Grid,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Container,
  IconButton,
  useMediaQuery
} from '@mui/material';
import {
  Dashboard,
  Security,
  NetworkCheck,
  Assessment,
  Settings,
  Menu as MenuIcon,
  TrendingUp
} from '@mui/icons-material';
import NetworkMonitoring from './components/NetworkMonitoring';
import ActivitiesFeed from './components/ActivitiesFeed';
import AnalyticsPage from './pages/AnalyticsPage';
import SettingsPage from './pages/SettingsPage';
import OverviewPage from './pages/OverviewPage';
import NetworkTargetsPage from './pages/NetworkTargetsPage';
import ScanEnginePage from './pages/ScanEnginePage';
import ThreatIntelligencePage from './pages/ThreatIntelligencePage';
import TelemetryLogsPage from './pages/TelemetryLogsPage';
import AnomalyDetectionPage from './pages/AnomalyDetectionPage';
import ReportsAnalyticsPage from './pages/ReportsAnalyticsPage';
import ComplianceCenterPage from './pages/ComplianceCenterPage';
import IncidentResponsePage from './pages/IncidentResponsePage';
import DemoControls from './components/DemoControls';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

const drawerWidth = 240;

function App() {
  const [selectedSection, setSelectedSection] = useState('dashboard');
  const [mobileOpen, setMobileOpen] = useState(false);
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const menuItems = [
    { id: 'overview', label: 'Overview', icon: <Dashboard /> },
    { id: 'network-targets', label: 'Network Targets', icon: <NetworkCheck /> },
    { id: 'scan-engine', label: 'Scan Engine', icon: <Security /> },
    { id: 'monitoring', label: 'Network Monitoring', icon: <NetworkCheck /> },
    { id: 'threat-intel', label: 'Threat Intelligence', icon: <Assessment /> },
    { id: 'telemetry', label: 'Telemetry & Logs', icon: <TrendingUp /> },
    { id: 'anomaly', label: 'Anomaly Detection', icon: <Security /> },
    { id: 'reports', label: 'Reports & Analytics', icon: <TrendingUp /> },
    { id: 'compliance', label: 'Compliance Center', icon: <Assessment /> },
    { id: 'incident', label: 'Incident Response', icon: <Security /> },
    { id: 'analytics', label: 'Analytics', icon: <TrendingUp /> },
    { id: 'settings', label: 'Settings', icon: <Settings /> },
  ];

  const drawer = (
    <div>
      <Toolbar>
        <Typography variant="h6" noWrap component="div">
          OSROVNet
        </Typography>
      </Toolbar>
      <List>
        {menuItems.map((item) => (
          <ListItem
            key={item.id}
            onClick={() => {
              setSelectedSection(item.id);
              if (isMobile) {
                setMobileOpen(false);
              }
            }}
            sx={{
              cursor: 'pointer',
              backgroundColor: selectedSection === item.id ? 'rgba(25, 118, 210, 0.12)' : 'transparent',
            }}
          >
            <ListItemIcon>{item.icon}</ListItemIcon>
            <ListItemText primary={item.label} />
          </ListItem>
        ))}
      </List>
    </div>
  );

  const renderContent = () => {
    switch (selectedSection) {
      case 'overview':
        return <OverviewPage />;
      case 'network-targets':
        return <NetworkTargetsPage />;
      case 'scan-engine':
        return <ScanEnginePage />;
      case 'dashboard':
        return (
          <Box>
            <Typography variant="h4" component="h1" gutterBottom>
              Dashboard
            </Typography>
            <Typography variant="body1">
              Welcome to OSROVNet - Your Network Security Monitoring Platform
            </Typography>
            <Box mt={4}>
              <Typography variant="h6" gutterBottom>
                Quick Actions
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Use the navigation menu to access different sections:
              </Typography>
              <List dense sx={{ mt: 1 }}>
                <ListItem>
                  <ListItemText primary="Network Monitoring - Real-time network scanning and analysis" />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Security Analysis - Vulnerability assessment and reporting" />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Threat Intelligence - Advanced threat detection and analysis" />
                </ListItem>
              </List>
            </Box>
          </Box>
        );
      case 'monitoring':
        return <NetworkMonitoring />;
      case 'threat-intel':
        return <ThreatIntelligencePage />;
      case 'telemetry':
        return <TelemetryLogsPage />;
      case 'anomaly':
        return <AnomalyDetectionPage />;
      case 'reports':
        return <ReportsAnalyticsPage />;
      case 'compliance':
        return <ComplianceCenterPage />;
      case 'incident':
        return <IncidentResponsePage />;
      case 'security':
        return (
          <Box>
            <Typography variant="h4" component="h1" gutterBottom>
              Security Analysis
            </Typography>
            <Typography variant="body1">
              Security analysis features will be implemented here.
            </Typography>
            <Box mt={2}>
              <DemoControls />
            </Box>
          </Box>
        );
      case 'threats':
        return (
          <Box>
            <Typography variant="h4" component="h1" gutterBottom>
              Threat Intelligence
            </Typography>
            <Typography variant="body1">
              Threat intelligence features will be implemented here.
            </Typography>
          </Box>
        );
      case 'analytics':
        return <AnalyticsPage />;
      case 'settings':
        return <SettingsPage />;
      default:
        return (
          <Box>
            <Typography variant="h4" component="h1" gutterBottom>
              Page Not Found
            </Typography>
          </Box>
        );
    }
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Box sx={{ display: 'flex' }}>
        <AppBar
          position="fixed"
          sx={{
            width: { md: `calc(100% - ${drawerWidth}px)` },
            ml: { md: `${drawerWidth}px` },
          }}
        >
          <Toolbar>
            <IconButton
              color="inherit"
              aria-label="open drawer"
              edge="start"
              onClick={handleDrawerToggle}
              sx={{ mr: 2, display: { md: 'none' } }}
            >
              <MenuIcon />
            </IconButton>
            <Typography variant="h6" noWrap component="div">
              OSROVNet - Network Security Platform
            </Typography>
          </Toolbar>
        </AppBar>
        
        <Box
          component="nav"
          sx={{ width: { md: drawerWidth }, flexShrink: { md: 0 } }}
        >
          <Drawer
            variant="temporary"
            open={mobileOpen}
            onClose={handleDrawerToggle}
            ModalProps={{
              keepMounted: true,
            }}
            sx={{
              display: { xs: 'block', md: 'none' },
              '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
            }}
          >
            {drawer}
          </Drawer>
          <Drawer
            variant="permanent"
            sx={{
              display: { xs: 'none', md: 'block' },
              '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
            }}
            open
          >
            {drawer}
          </Drawer>
        </Box>
        
        <Box
            component="main"
            sx={{
              flexGrow: 1,
              p: 3,
              width: { md: `calc(100% - ${drawerWidth}px)` },
            }}
          >
          <Toolbar />
            <Container maxWidth="xl">
              {selectedSection === 'dashboard' ? (
                <Grid container spacing={3}>
                  <Grid item xs={12} md={8}>
                    {renderContent()}
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <ActivitiesFeed />
                  </Grid>
                </Grid>
              ) : (
                renderContent()
              )}
            </Container>
        </Box>
      </Box>
    </ThemeProvider>
  );
}

export default App;
