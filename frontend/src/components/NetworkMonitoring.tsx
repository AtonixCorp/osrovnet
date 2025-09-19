import React, { useState, useEffect } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  CircularProgress,
  Alert,
  Box,
  Chip,
  List,
  ListItem,
  ListItemText,
  Divider,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel
} from '@mui/material';
import {
  Security,
  Computer,
  NetworkCheck,
  Warning,
  Refresh,
  Add,
  PlayArrow
} from '@mui/icons-material';
import ScanResultsDialog from './ScanResultsDialog';
import api from '../api/osrovnetApi';

interface NetworkTarget {
  id: number;
  name: string;
  target: string;
  scan_type: string;
  ports: string;
  is_active: boolean;
  scan_count: number;
  created_at: string;
}

interface NetworkScan {
  id: number;
  status: string;
  started_at: string;
  completed_at?: string;
  hosts_discovered: number;
  ports_scanned: number;
  vulnerabilities_found: number;
  target_details: NetworkTarget;
}

interface DashboardStats {
  total_scans: number;
  completed_scans: number;
  failed_scans: number;
  running_scans: number;
  total_hosts: number;
  total_ports: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  recent_alerts: number;
}

interface NetworkOverview {
  active_hosts: number;
  total_ports_open: number;
  recent_scans: number;
  active_alerts: number;
  top_services: Array<{ service_name: string; count: number }>;
  vulnerability_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  traffic_summary: {
    total_packets: number;
    unique_sources: number;
    unique_destinations: number;
  };
}

const NetworkMonitoring: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [overview, setOverview] = useState<NetworkOverview | null>(null);
  const [targets, setTargets] = useState<NetworkTarget[]>([]);
  const [scans, setScans] = useState<NetworkScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [quickScanDialog, setQuickScanDialog] = useState(false);
  const [quickScanData, setQuickScanData] = useState({
    target: '',
    scan_type: 'quick',
    ports: '1-1000',
    name: ''
  });
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [portScanTarget, setPortScanTarget] = useState('');
  const [portScanPorts, setPortScanPorts] = useState('1-1000');
  const [wifiScanInterface, setWifiScanInterface] = useState('wlan0');
  const [dnsScanTarget, setDnsScanTarget] = useState('');
  const [scanDialogOpen, setScanDialogOpen] = useState(false);
  const [activeScanId, setActiveScanId] = useState<number | undefined>(undefined);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);

      const statsData = await api.Analytics.metrics('dashboard/statistics/');
      setStats(statsData);

      const overviewData = await api.Analytics.metrics('dashboard/overview/');
      setOverview(overviewData);

      const targetsData = await api.Targets.list();
      setTargets(targetsData.results || targetsData || []);

      const scansData = await api.Scans.list('?ordering=-started_at&limit=10');
      setScans(scansData.results || scansData || []);

    } catch (err) {
      setError('Failed to fetch network monitoring data. Make sure the Django server is running.');
      console.error('API Error:', err);
    } finally {
      setLoading(false);
    }
  };

  const startQuickScan = async () => {
    try {
      await api.QuickScan(quickScanData);
      setQuickScanDialog(false);
      setQuickScanData({ target: '', scan_type: 'quick', ports: '1-1000', name: '' });
      setTimeout(fetchData, 1000);
    } catch (err) {
      setError('Failed to start quick scan');
      console.error('Quick scan error:', err);
    }
  };

  const startTargetScan = async (targetId: number) => {
    try {
      const data = await api.Targets.startScan(targetId);
      const scanId = data.id || data.scan_id;
      setActiveScanId(scanId);
      setScanDialogOpen(true);
      setTimeout(fetchData, 1000);
    } catch (err) {
      console.error('startTargetScan error', err);
      setError('Failed to start target scan');
    }
  };

  useEffect(() => {
    fetchData();
    // Refresh data every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'warning';
      case 'completed': return 'success';
      case 'failed': return 'error';
      default: return 'default';
    }
  };

  if (loading && !stats) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
        <Typography variant="h6" sx={{ ml: 2 }}>
          Loading network monitoring data...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1" gutterBottom>
          Network Security Monitoring
        </Typography>
        <Box>
          <Button
            variant="outlined"
            startIcon={<Add />}
            onClick={() => setQuickScanDialog(true)}
            sx={{ mr: 1 }}
          >
            Quick Scan
          </Button>
          <Button
            variant="outlined"
            onClick={() => setAdvancedOpen(!advancedOpen)}
            sx={{ mr: 1 }}
          >
            Advanced Scans
          </Button>
          <Button
            variant="outlined"
            startIcon={<Refresh />}
            onClick={fetchData}
            disabled={loading}
          >
            Refresh
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Dashboard Statistics */}
      {stats && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <NetworkCheck color="primary" sx={{ mr: 1 }} />
                  <div>
                    <Typography color="textSecondary" gutterBottom>
                      Total Scans
                    </Typography>
                    <Typography variant="h4">
                      {stats.total_scans}
                    </Typography>
                  </div>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <Computer color="primary" sx={{ mr: 1 }} />
                  <div>
                    <Typography color="textSecondary" gutterBottom>
                      Discovered Hosts
                    </Typography>
                    <Typography variant="h4">
                      {stats.total_hosts}
                    </Typography>
                  </div>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <Security color="primary" sx={{ mr: 1 }} />
                  <div>
                    <Typography color="textSecondary" gutterBottom>
                      Vulnerabilities
                    </Typography>
                    <Typography variant="h4">
                      {stats.total_vulnerabilities}
                    </Typography>
                  </div>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <Warning color="error" sx={{ mr: 1 }} />
                  <div>
                    <Typography color="textSecondary" gutterBottom>
                      Active Alerts
                    </Typography>
                    <Typography variant="h4">
                      {stats.recent_alerts}
                    </Typography>
                  </div>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      <Grid container spacing={3}>
        {/* Network Overview */}
        {overview && (
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Network Overview
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography color="textSecondary">Active Hosts</Typography>
                    <Typography variant="h6">{overview.active_hosts}</Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography color="textSecondary">Open Ports</Typography>
                    <Typography variant="h6">{overview.total_ports_open}</Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography color="textSecondary">Recent Scans</Typography>
                    <Typography variant="h6">{overview.recent_scans}</Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography color="textSecondary">Active Alerts</Typography>
                    <Typography variant="h6">{overview.active_alerts}</Typography>
                  </Grid>
                </Grid>

                {overview.vulnerability_breakdown && (
                  <Box mt={2}>
                    <Typography variant="subtitle2" gutterBottom>
                      Vulnerability Breakdown
                    </Typography>
                    <Box display="flex" flexWrap="wrap" gap={1}>
                      {Object.entries(overview.vulnerability_breakdown).map(([severity, count]) => (
                        <Chip
                          key={severity}
                          label={`${severity}: ${count}`}
                          color={getSeverityColor(severity) as any}
                          size="small"
                        />
                      ))}
                    </Box>
                  </Box>
                )}
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Recent Scans */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Scans
              </Typography>
              <List dense>
                {scans.length > 0 ? (
                  scans.slice(0, 5).map((scan) => (
                    <React.Fragment key={scan.id}>
                      <ListItem>
                        <ListItemText
                          primary={scan.target_details?.name || `Scan #${scan.id}`}
                          secondary={
                            <Box>
                              <Box display="flex" alignItems="center" gap={1}>
                                <Chip
                                  label={scan.status}
                                  color={getStatusColor(scan.status) as any}
                                  size="small"
                                />
                                <Typography variant="caption">
                                  {new Date(scan.started_at).toLocaleString()}
                                </Typography>
                              </Box>
                              {scan.status === 'completed' && (
                                <Typography variant="caption" display="block">
                                  Hosts: {scan.hosts_discovered} | Vulnerabilities: {scan.vulnerabilities_found}
                                </Typography>
                              )}
                            </Box>
                          }
                        />
                      </ListItem>
                      <Divider />
                    </React.Fragment>
                  ))
                ) : (
                  <Typography color="textSecondary" align="center">
                    No scans available. Start a quick scan to begin monitoring.
                  </Typography>
                )}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* Network Targets */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Network Targets
              </Typography>
              <List>
                {targets.length > 0 ? (
                  targets.map((target) => (
                    <React.Fragment key={target.id}>
                      <ListItem>
                        <ListItemText
                          primary={target.name}
                          secondary={
                            <Box>
                              <Typography variant="body2">
                                Target: {target.target} | Type: {target.scan_type} | Ports: {target.ports}
                              </Typography>
                              <Box display="flex" alignItems="center" gap={1} mt={1}>
                                <Chip
                                  label={target.is_active ? 'Active' : 'Inactive'}
                                  color={target.is_active ? 'success' : 'default'}
                                  size="small"
                                />
                                <Typography variant="caption">
                                  Scans: {target.scan_count}
                                </Typography>
                                <Button variant="outlined" size="small" onClick={() => startTargetScan(target.id)} sx={{ ml: 1 }}>Start Scan</Button>
                              </Box>
                            </Box>
                          }
                        />
                      </ListItem>
                      <Divider />
                    </React.Fragment>
                  ))
                ) : (
                  <Typography color="textSecondary" align="center">
                    No network targets configured. Add targets to start monitoring.
                  </Typography>
                )}
              </List>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Quick Scan Dialog */}
      <Dialog open={quickScanDialog} onClose={() => setQuickScanDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Quick Network Scan</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            <TextField
              fullWidth
              label="Target (IP/Range/Domain)"
              value={quickScanData.target}
              onChange={(e) => setQuickScanData({ ...quickScanData, target: e.target.value })}
              placeholder="192.168.1.1 or 192.168.1.0/24 or example.com"
              sx={{ mb: 2 }}
            />
            <TextField
              fullWidth
              label="Scan Name (Optional)"
              value={quickScanData.name}
              onChange={(e) => setQuickScanData({ ...quickScanData, name: e.target.value })}
              placeholder="Quick scan of local network"
              sx={{ mb: 2 }}
            />
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Scan Type</InputLabel>
              <Select
                value={quickScanData.scan_type}
                onChange={(e) => setQuickScanData({ ...quickScanData, scan_type: e.target.value })}
              >
                <MenuItem value="quick">Quick Scan</MenuItem>
                <MenuItem value="comprehensive">Comprehensive Scan</MenuItem>
                <MenuItem value="stealth">Stealth Scan</MenuItem>
                <MenuItem value="discovery">Host Discovery</MenuItem>
              </Select>
            </FormControl>
            <TextField
              fullWidth
              label="Port Range"
              value={quickScanData.ports}
              onChange={(e) => setQuickScanData({ ...quickScanData, ports: e.target.value })}
              placeholder="1-1000 or 22,80,443"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setQuickScanDialog(false)}>Cancel</Button>
          <Button
            onClick={startQuickScan}
            variant="contained"
            startIcon={<PlayArrow />}
            disabled={!quickScanData.target}
          >
            Start Scan
          </Button>
        </DialogActions>
      </Dialog>

      {/* Advanced Scans Inline Panel */}
      {advancedOpen && (
        <Box sx={{ mt: 3, mb: 3 }}>
          <Card>
            <CardContent>
              <Typography variant="h6">Advanced Scans</Typography>
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mt: 2 }}>
                {/* Port Scan */}
                <Box sx={{ minWidth: 260 }}>
                  <Typography variant="subtitle2">Port Scan</Typography>
                  <TextField
                    fullWidth
                    size="small"
                    label="Target (IP/Range/Domain)"
                    value={portScanTarget}
                    onChange={(e) => setPortScanTarget(e.target.value)}
                    sx={{ mt: 1, mb: 1 }}
                    placeholder="192.168.1.1 or 10.0.0.0/24"
                  />
                  <TextField
                    fullWidth
                    size="small"
                    label="Ports"
                    value={portScanPorts}
                    onChange={(e) => setPortScanPorts(e.target.value)}
                    placeholder="1-1000 or 22,80,443"
                  />
                  <Button
                    variant="contained"
                    sx={{ mt: 1 }}
                    onClick={async () => {
                      try {
                        await api.QuickScan({ target: portScanTarget, scan_type: 'port', ports: portScanPorts });
                        setPortScanTarget('');
                        setPortScanPorts('1-1000');
                        setTimeout(fetchData, 1000);
                      } catch (e) {
                        console.error('port scan error', e);
                        setError('Failed to start port scan');
                      }
                    }}
                  >
                    Start Port Scan
                  </Button>
                </Box>

                {/* WiFi Scan */}
                <Box sx={{ minWidth: 260 }}>
                  <Typography variant="subtitle2">WiFi Scan</Typography>
                  <TextField
                    fullWidth
                    size="small"
                    label="Interface"
                    value={wifiScanInterface}
                    onChange={(e) => setWifiScanInterface(e.target.value)}
                    sx={{ mt: 1, mb: 1 }}
                    placeholder="wlan0"
                  />
                  <Typography variant="caption" color="textSecondary">Performs passive WiFi discovery and signal mapping (requires agent support).</Typography>
                  <Button
                    variant="contained"
                    sx={{ mt: 1 }}
                    onClick={async () => {
                      try {
                        await api.QuickScan({ interface: wifiScanInterface, scan_type: 'wifi' });
                        setWifiScanInterface('wlan0');
                        setTimeout(fetchData, 1000);
                      } catch (e) {
                        console.error('wifi scan error', e);
                        setError('Failed to start wifi scan');
                      }
                    }}
                  >
                    Start WiFi Scan
                  </Button>
                </Box>

                {/* DNS Scan */}
                <Box sx={{ minWidth: 260 }}>
                  <Typography variant="subtitle2">DNS Enumeration</Typography>
                  <TextField
                    fullWidth
                    size="small"
                    label="Domain"
                    value={dnsScanTarget}
                    onChange={(e) => setDnsScanTarget(e.target.value)}
                    sx={{ mt: 1, mb: 1 }}
                    placeholder="example.com"
                  />
                  <Typography variant="caption" color="textSecondary">Run DNS enumeration (NS, MX, zone transfer attempts where allowed).</Typography>
                  <Button
                    variant="contained"
                    sx={{ mt: 1 }}
                    onClick={async () => {
                      try {
                        await api.QuickScan({ domain: dnsScanTarget, scan_type: 'dns' });
                        setDnsScanTarget('');
                        setTimeout(fetchData, 1000);
                      } catch (e) {
                        console.error('dns scan error', e);
                        setError('Failed to start dns scan');
                      }
                    }}
                  >
                    Start DNS Scan
                  </Button>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Box>
      )}
      <ScanResultsDialog open={scanDialogOpen} scanId={activeScanId} onClose={() => { setScanDialogOpen(false); setActiveScanId(undefined); }} />
    </Box>
  );
};

export default NetworkMonitoring;