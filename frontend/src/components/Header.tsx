import React from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  IconButton,
  Drawer,
  List,
  ListItemButton,
  ListItemText,
  Box,
  Divider,
  useMediaQuery,
  useTheme,
  Link as MuiLink,
} from '@mui/material';
import LightModeIcon from '@mui/icons-material/LightMode';
import DarkModeIcon from '@mui/icons-material/DarkMode';
import MenuIcon from '@mui/icons-material/Menu';
import { useAuth } from '../auth/AuthProvider';
import './Header.css';

const navItems = [
  { label: 'Home', href: '#/' },
  { label: 'Intelligence', href: '#/intelligence' },
  { label: 'Support', href: '#/support' },
  { label: 'Documentation', href: '#/documentation' },
  { label: 'Community', href: '#/community' },
  { label: 'Security', href: '#/security' },
  { label: 'Blog', href: '#/blog' },
  { label: 'Vulnerability', href: '#/vulnerabilities' },
  { label: 'Post-Quantum', href: '#/postquantum' },
];

// Styles used by the header component. Kept outside the function so they can be
// referenced directly from the JSX (sx={...}). navLink is a small factory that
// returns a style object depending on whether the link is active.
const headerStyles = {
  appBar: {
    // use theme tokens where possible; MUI will resolve these at render time
    backgroundColor: 'primary.main',
    color: 'common.white',
  },
  logo: {
    fontWeight: 700,
    letterSpacing: '0.5px',
  },
  subtitle: {
    fontSize: '0.72rem',
    opacity: 0.9,
    lineHeight: 1,
  },
  navLink: (active: boolean) => ({
    px: 1.25,
    py: 0.5,
    borderBottom: active ? '2px solid' : '2px solid transparent',
    borderColor: active ? 'secondary.main' : 'transparent',
    fontWeight: active ? 600 : 400,
    transition: 'border-color 150ms ease',
    '&:hover': { textDecoration: 'none', opacity: 0.9 },
  }),
  drawer: {
    backgroundColor: 'background.paper',
    height: '100%',
  },
};

export default function Header({ mode, toggleMode }: { mode?: 'light' | 'dark'; toggleMode?: () => void }) {
  const { user, logout } = useAuth();
  const theme = useTheme();
  const isSmall = useMediaQuery(theme.breakpoints.down('md'));
  const [open, setOpen] = React.useState(false);
  const [currentHash, setCurrentHash] = React.useState<string>(window.location.hash || '#/');

  React.useEffect(() => {
    const handler = () => setCurrentHash(window.location.hash || '#/');
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  }, []);

  const toggleDrawer = (next: boolean) => () => setOpen(next);

  return (
    <AppBar position="static" sx={headerStyles.appBar}>
      <Toolbar sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Box sx={{ display: 'flex', flexDirection: 'column' }}>
            <Typography variant="h6" sx={headerStyles.logo}>
              Osrovnet
            </Typography>
            <Typography variant="caption" sx={headerStyles.subtitle}>
              Network Security Platform
            </Typography>
          </Box>
        </Box>

        {!isSmall && (
          <Box component="nav" sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
            {navItems.map((it) => {
              const active = currentHash === it.href;
              return (
                <MuiLink
                  key={it.href}
                  href={it.href}
                  color="inherit"
                  underline="none"
                  sx={headerStyles.navLink(active)}
                >
                  {it.label}
                </MuiLink>
              );
            })}
          </Box>
        )}

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {!isSmall ? (
            <>
              {/* Theme toggle is visible to everyone */}
              <IconButton color="inherit" onClick={() => toggleMode && toggleMode()} aria-label="Toggle theme">
                {mode === 'dark' ? <LightModeIcon /> : <DarkModeIcon />}
              </IconButton>
              {user ? (
                <>
                  <Button color="inherit" href="#/">Home</Button>
                  <Button color="inherit" onClick={() => logout()}>
                    Logout
                  </Button>
                </>
              ) : (
                <>
                  <Button color="inherit" href="#/login">
                    Login
                  </Button>
                  <Button color="inherit" href="#/signup">
                    Sign up
                  </Button>
                </>
              )}
            </>
          ) : (
            <>
              <IconButton color="inherit" onClick={toggleDrawer(true)} edge="end">
                <MenuIcon />
              </IconButton>
              <Drawer anchor="right" open={open} onClose={toggleDrawer(false)}>
                <Box sx={{ width: 260, ...headerStyles.drawer }} role="presentation" onClick={toggleDrawer(false)}>
                  <List>
                    {navItems.map((it) => (
                      <ListItemButton
                        component="a"
                        href={it.href}
                        key={it.href}
                        selected={currentHash === it.href}
                      >
                        <ListItemText primary={it.label} />
                      </ListItemButton>
                    ))}
                  </List>
                  <Divider />
                  <List>
                    {mode && toggleMode && (
                      <ListItemButton onClick={() => toggleMode && toggleMode()}>
                        <ListItemText primary={mode === 'dark' ? 'Switch to light' : 'Switch to dark'} />
                      </ListItemButton>
                    )}
                    {user ? (
                      <ListItemButton onClick={() => logout()}>
                        <ListItemText primary="Logout" />
                      </ListItemButton>
                    ) : (
                      <>
                        <ListItemButton component="a" href="#/login">
                          <ListItemText primary="Login" />
                        </ListItemButton>
                        <ListItemButton component="a" href="#/signup">
                          <ListItemText primary="Sign up" />
                        </ListItemButton>
                      </>
                    )}
                  </List>
                </Box>
              </Drawer>
            </>
          )}
        </Box>
      </Toolbar>
    </AppBar>
  );
}