import React, { useEffect, useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  CircularProgress,
  Box,
  Chip,
} from '@mui/material';
import { getHealthStatus } from '../services/api';

const HealthStatusWidget = () => {
  const [healthStatus, setHealthStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchHealthStatus = async () => {
    try {
      const data = await getHealthStatus();
      setHealthStatus(data);
    } catch (err) {
      setError(err);
      console.error('Error fetching health status:', err);
      setHealthStatus({ status: 'Degraded', database: 'Degraded' }); // Assume degraded on error
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealthStatus();
    const interval = setInterval(fetchHealthStatus, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status) => {
    if (status === 'Healthy') return 'success';
    if (status === 'Degraded') return 'error';
    return 'warning'; // For 'Recovering' or unknown
  };

  if (loading) {
    return (
      <Card>
        <CardContent>
          <Box
            display="flex"
            justifyContent="center"
            alignItems="center"
            minHeight="100px"
          >
            <CircularProgress />
          </Box>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Service Health
        </Typography>
        <Box display="flex" alignItems="center" mb={1}>
          <Typography variant="subtitle1" mr={1}>
            Overall Status:
          </Typography>
          <Chip
            label={healthStatus?.status || 'Unknown'}
            color={getStatusColor(healthStatus?.status)}
            size="small"
          />
        </Box>
        <Box display="flex" alignItems="center">
          <Typography variant="subtitle1" mr={1}>
            Database:
          </Typography>
          <Chip
            label={healthStatus?.database || 'Unknown'}
            color={getStatusColor(healthStatus?.database)}
            size="small"
          />
        </Box>
        {error && (
          <Typography color="error" variant="body2" mt={2}>
            Error: {error.message || 'Could not connect to health endpoint.'}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
};

export default HealthStatusWidget;
