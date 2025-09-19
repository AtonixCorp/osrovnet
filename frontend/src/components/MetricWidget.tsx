import React, { useEffect, useState } from 'react';
import { Card, CardContent, Typography } from '@mui/material';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend);

interface Props {
  metricName: string;
  title?: string;
}

const MetricWidget: React.FC<Props> = ({ metricName, title }) => {
  const [data, setData] = useState<number[]>([]);

  useEffect(() => {
    let mounted = true;
    const fetchData = async () => {
      try {
        const json = await (await import('../api/osrovnetApi')).default.Analytics.metrics(`?name=${metricName}&limit=50`);
        if (!mounted) return;
        const items = json.results || json || [];
        setData(items.map((i: any) => i.value || 0).reverse());
      } catch (e) {
        // ignore
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => { mounted = false; clearInterval(interval); };
  }, [metricName]);

  const chartData = {
    labels: data.map((_, i) => i.toString()),
    datasets: [
      {
        label: title || metricName,
        data,
        borderColor: '#1976d2',
        backgroundColor: 'rgba(25,118,210,0.1)',
        tension: 0.2,
      }
    ]
  };

  return (
    <Card>
      <CardContent>
        <Typography variant="subtitle1">{title || metricName}</Typography>
        <Line data={chartData} />
      </CardContent>
    </Card>
  );
};

export default MetricWidget;
