import React, { useState } from 'react';
import { Card, CardContent, Typography, TextField, Button } from '@mui/material';
import api from '../api/osrovnetApi';

const ReportBuilder: React.FC = () => {
  const [jsonDef, setJsonDef] = useState<string>('{}');

  const save = async () => {
    try {
      const payload = JSON.parse(jsonDef || '{}');
  // For now, POST to reports to create a new ReportDefinition
  await api.request('/analytics/reports/', { method: 'POST', body: JSON.stringify({ name: 'Ad-hoc', definition: payload }) });
      alert('Saved (refresh to see)');
    } catch (e) {
      alert('Invalid JSON');
    }
  };

  return (
    <Card>
      <CardContent>
        <Typography variant="h6">Report Builder (JSON)</Typography>
        <TextField
          multiline
          minRows={8}
          fullWidth
          value={jsonDef}
          onChange={(e) => setJsonDef(e.target.value)}
        />
        <Button variant="contained" sx={{ mt: 1 }} onClick={save}>Save Report</Button>
      </CardContent>
    </Card>
  );
};

export default ReportBuilder;
