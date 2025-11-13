import React, { useEffect, useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  CircularProgress,
  Box,
  List,
  ListItem,
  ListItemText,
  Chip,
} from '@mui/material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import {
  getTrustMetrics,
  getSecurityAlerts,
  getSessions,
} from '../services/api';

const SecurityInsightsCard = () => {
  const [trustScore, setTrustScore] = useState(null);
  const [securityAlerts, setSecurityAlerts] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [trustData, alertsData, sessionsData] = await Promise.all([
          getTrustMetrics(),
          getSecurityAlerts(),
          getSessions(),
        ]);
        setTrustScore(trustData.trust_score);
        setSecurityAlerts(alertsData);
        setSessions(sessionsData);
      } catch (err) {
        setError(err);
        console.error('Error fetching security insights:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const getTrustScoreColor = (score) => {
    if (score >= 80) return 'success';
    if (score >= 50) return 'warning';
    return 'error';
  };

  if (loading) {
    return (
      <Card>
        <CardContent>
          <Box
            display="flex"
            justifyContent="center"
            alignItems="center"
            minHeight="200px"
          >
            <CircularProgress />
          </Box>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent>
          <Typography color="error">
            Error loading security insights: {error.message}
          </Typography>
        </CardContent>
      </Card>
    );
  }

  // Prepare data for anomaly frequency chart
  const anomalyFrequencyData = securityAlerts
    .reduce((acc, alert) => {
      const date = new Date(alert.timestamp).toLocaleDateString();
      const existing = acc.find((item) => item.date === date);
      if (existing) {
        existing.count += 1;
      } else {
        acc.push({ date, count: 1 });
      }
      return acc;
    }, [])
    .sort((a, b) => new Date(a.date) - new Date(b.date));

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Security Insights
        </Typography>

        <Box mb={2}>
          <Typography variant="subtitle1">Current Trust Score:</Typography>
          <Chip
            label={trustScore !== null ? trustScore.toFixed(2) : 'N/A'}
            color={getTrustScoreColor(trustScore)}
            size="small"
          />
        </Box>

        <Box mb={2}>
          <Typography variant="subtitle1">Recent Security Alerts:</Typography>
          <List dense>
            {securityAlerts.slice(0, 5).map((alert, index) => (
              <ListItem key={index}>
                <ListItemText
                  primary={alert.message}
                  secondary={`IP: ${alert.ip_address} - ${new Date(alert.timestamp).toLocaleString()}`}
                />
                <Chip
                  label={alert.risk_level}
                  color={alert.risk_level === 'High' ? 'error' : 'warning'}
                  size="small"
                />
              </ListItem>
            ))}
            {securityAlerts.length === 0 && (
              <Typography variant="body2">No recent alerts.</Typography>
            )}
          </List>
        </Box>

        <Box mb={2}>
          <Typography variant="subtitle1">
            Anomaly Frequency Over Time:
          </Typography>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={anomalyFrequencyData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line
                type="monotone"
                dataKey="count"
                stroke="#8884d8"
                activeDot={{ r: 8 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </Box>

        <Box>
          <Typography variant="subtitle1">Active Sessions:</Typography>
          <List dense>
            {sessions.map((session, index) => (
              <ListItem key={index}>
                <ListItemText
                  primary={`Session from ${session.ip}`}
                  secondary={`Device: ${session.user_agent || 'N/A'} - Created: ${new Date(session.created_at).toLocaleString()}`}
                />
              </ListItem>
            ))}
            {sessions.length === 0 && (
              <Typography variant="body2">No active sessions.</Typography>
            )}
          </List>
        </Box>
      </CardContent>
    </Card>
  );
};

export default SecurityInsightsCard;
