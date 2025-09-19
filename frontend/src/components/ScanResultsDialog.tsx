import React, { useEffect, useState } from 'react';
import { Dialog, DialogTitle, DialogContent, DialogActions, Button, Typography, List, ListItem, ListItemText } from '@mui/material';
import api from '../api/osrovnetApi';

const ScanResultsDialog: React.FC<{ open: boolean; scanId?: number; onClose: () => void }> = ({ open, scanId, onClose }) => {
  const [scan, setScan] = useState<any | null>(null);

  useEffect(() => {
    let mounted = true;
    const fetchScan = async () => {
      if (!scanId) return;
      try {
        const data = await api.Scans.retrieve(scanId);
        if (!mounted) return;
        setScan(data);
      } catch (e) {
        console.error('fetchScan error', e);
      }
    };
    fetchScan();
    const interval = setInterval(fetchScan, 5000);
    return () => { mounted = false; clearInterval(interval); };
  }, [scanId]);

  const exportCSV = () => {
    if (!scan) return;
    const rows: string[] = ['host,port,protocol,service,version,severity,cve,description'];
    for (const h of scan.hosts || []) {
      for (const p of h.ports || []) {
        for (const v of p.vulnerabilities || []) {
          // eslint-disable-next-line no-useless-escape
          rows.push(`${h.ip_address},${p.port_number},${p.protocol},${p.service_name},${p.service_version},${v.severity},${v.cve_id || ''},"${(v.description||'').replace(/\"/g,'\"\"')}"`);
        }
      }
    }
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-${scanId}-vulnerabilities.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="lg">
      <DialogTitle>Scan Results {scanId ? `#${scanId}` : ''}</DialogTitle>
      <DialogContent>
        {!scan ? <Typography>Loading...</Typography> : (
          <div>
            <Typography variant="subtitle1">Status: {scan.status}</Typography>
            <Typography variant="subtitle2">Hosts Discovered: {scan.hosts_discovered}</Typography>
            <List>
              {(scan.hosts || []).map((h: any) => (
                <ListItem key={h.id}>
                  <ListItemText primary={`${h.ip_address} • ${h.hostname || ''}`} secondary={`Ports: ${h.port_count} • Vulns: ${h.vulnerability_count}`} />
                </ListItem>
              ))}
            </List>
          </div>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={exportCSV} disabled={!scan}>Export Vulnerabilities (CSV)</Button>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default ScanResultsDialog;
