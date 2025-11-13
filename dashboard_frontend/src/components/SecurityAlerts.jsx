import React, { useState, useEffect } from 'react';
import { getSecurityAlerts } from '../services/api';

const SecurityAlerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const data = await getSecurityAlerts();
        setAlerts(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchAlerts();
  }, []);

  if (loading) {
    return <div>Loading security alerts...</div>;
  }

  if (error) {
    return <div className="text-red-500">Error: {error}</div>;
  }

  return (
    <div className="bg-white shadow-md rounded-lg p-6">
      <h2 className="text-2xl font-bold mb-4">Security Alerts</h2>
      {alerts.length === 0 ? (
        <p>No security alerts at the moment.</p>
      ) : (
        <ul>
          {alerts.map((alert, index) => (
            <li key={index} className="border-b last:border-b-0 py-2">
              <p className="font-semibold">{alert.message}</p>
              <p className="text-sm text-gray-600">
                IP: {alert.ip_address} | Risk Level: {alert.risk_level}
              </p>
              <p className="text-xs text-gray-400">
                {new Date(alert.timestamp).toLocaleString()}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default SecurityAlerts;
