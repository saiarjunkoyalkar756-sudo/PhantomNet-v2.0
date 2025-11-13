import React, { useState, useEffect } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from 'recharts';
import {
  getTrustMetrics,
  getSecurityAlerts,
  getSessions,
} from '../services/api';

const SecurityInsights = () => {
  const [trustScore, setTrustScore] = useState(0);
  const [alerts, setAlerts] = useState([]);
  const [sessions, setSessions] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const trustScoreData = await getTrustMetrics();
        setTrustScore(trustScoreData.trust_score);

        const alertsData = await getSecurityAlerts();
        setAlerts(alertsData);

        const sessionsData = await getSessions();
        setSessions(sessionsData);
      } catch (error) {
        console.error('Error fetching security insights:', error);
      }
    };

    fetchData();
  }, []);

  const getTrustScoreColor = (score) => {
    if (score > 70) return 'text-green-500';
    if (score > 40) return 'text-yellow-500';
    return 'text-red-500';
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-4">Security Insights</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <h3 className="text-lg font-semibold mb-2">Trust Score</h3>
          <p className={`text-4xl font-bold ${getTrustScoreColor(trustScore)}`}>
            {trustScore.toFixed(1)}
          </p>
        </div>
        <div>
          <h3 className="text-lg font-semibold mb-2">Anomaly Frequency</h3>
          <BarChart width={500} height={300} data={alerts}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="timestamp" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="risk_level" fill="#8884d8" />
          </BarChart>
        </div>
      </div>
      <div className="mt-6">
        <h3 className="text-lg font-semibold mb-2">Recent Security Alerts</h3>
        <ul className="divide-y divide-gray-200">
          {alerts.slice(0, 5).map((alert, index) => (
            <li key={index} className="py-2">
              <p className="text-sm text-gray-600">{alert.timestamp}</p>
              <p className="font-medium">{alert.message}</p>
            </li>
          ))}
        </ul>
      </div>
      <div className="mt-6">
        <h3 className="text-lg font-semibold mb-2">Active Sessions</h3>
        <ul className="divide-y divide-gray-200">
          {sessions.map((session, index) => (
            <li key={index} className="py-2">
              <p className="text-sm text-gray-600">IP: {session.ip}</p>
              <p className="font-medium">Device: {session.user_agent}</p>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default SecurityInsights;
