import React, { useEffect, useState } from 'react';
import { Card, CardContent, Typography, List, ListItem, ListItemText, Button, Dialog, DialogTitle, DialogContent, TextField, DialogActions } from '@mui/material';
import api from '../api/osrovnetApi';

const TargetManager: React.FC<{ onStartScan: (targetId: number) => void }> = ({ onStartScan }) => {
  const [targets, setTargets] = useState<any[]>([]);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: '', target: '', ports: '1-1000', scan_type: 'tcp' });

  const fetchTargets = async () => {
    try {
      const data = await api.Targets.list();
      setTargets(data.results || data || []);
    } catch (e) {
      console.error('fetchTargets error', e);
    }
  };

  useEffect(() => { fetchTargets(); }, []);

  const save = async () => {
    try {
      await api.Targets.create(form);
      setOpen(false);
      fetchTargets();
    } catch (e) {
      console.error('save target error', e);
    }
  };

  return (
    <Card>
      <CardContent>
        <Typography variant="h6">Targets</Typography>
        <List>
          {targets.map(t => (
            <ListItem key={t.id} secondaryAction={<Button onClick={() => onStartScan(t.id)}>Start Scan</Button>}>
              <ListItemText primary={t.name} secondary={`${t.target} • ${t.scan_type} • ports: ${t.ports}`} />
            </ListItem>
          ))}
        </List>
        <Button onClick={() => setOpen(true)} variant="outlined">Add Target</Button>

        <Dialog open={open} onClose={() => setOpen(false)}>
          <DialogTitle>Add Target</DialogTitle>
          <DialogContent>
            <TextField fullWidth label="Name" value={form.name} onChange={(e) => setForm({...form, name: e.target.value})} sx={{mb:1}} />
            <TextField fullWidth label="Target (IP/Range/Host)" value={form.target} onChange={(e) => setForm({...form, target: e.target.value})} sx={{mb:1}} />
            <TextField fullWidth label="Ports" value={form.ports} onChange={(e) => setForm({...form, ports: e.target.value})} sx={{mb:1}} />
            <TextField fullWidth label="Scan Type" value={form.scan_type} onChange={(e) => setForm({...form, scan_type: e.target.value})} sx={{mb:1}} />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={save} variant="contained">Save</Button>
          </DialogActions>
        </Dialog>
      </CardContent>
    </Card>
  );
};

export default TargetManager;
