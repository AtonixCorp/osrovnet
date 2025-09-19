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
    { id: 'dashboard', label: 'Dashboard', icon: <Dashboard /> },
    { id: 'monitoring', label: 'Network Monitoring', icon: <NetworkCheck /> },
    { id: 'security', label: 'Security Analysis', icon: <Security /> },
    { id: 'threats', label: 'Threat Intelligence', icon: <Assessment /> },
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
      case 'security':
        return (
          <Box>
            <Typography variant="h4" component="h1" gutterBottom>
              Security Analysis
            </Typography>
            <Typography variant="body1">
              Security analysis features will be implemented here.
            </Typography>
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
        return (
          <Box>
            <Typography variant="h4" component="h1" gutterBottom>
              Settings
            </Typography>
            <Typography variant="body1">
              Application settings will be implemented here.
            </Typography>
          </Box>
        );
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
