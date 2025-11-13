import React, { useState, useEffect } from 'react';
import { getHealthStatus } from '../services/api';

const HealthStatus = () => {
  const [health, setHealth] = useState(null);

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const data = await getHealthStatus();
        setHealth(data);
      } catch (error) {
        console.error('Error fetching health status:', error);
      }
    };

    fetchHealth();
    const interval = setInterval(fetchHealth, 60000); // Fetch every minute

    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status) => {
    if (status === 'Healthy') return 'bg-green-500';
    if (status === 'Recovering') return 'bg-yellow-500';
    return 'bg-red-500';
  };

  if (!health) {
    return <div>Loading health status...</div>;
  }

  return (
    <div className="bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-4">System Health</h2>
      <div className="flex items-center">
        <div
          className={`w-4 h-4 rounded-full mr-2 ${getStatusColor(health.status)}`}
        ></div>
        <p className="text-lg font-semibold">{health.status}</p>
      </div>
      <div className="mt-4">
        <h3 className="text-lg font-semibold">Services</h3>
        <ul className="divide-y divide-gray-200">
          {Object.entries(health).map(([service, status]) => (
            <li key={service} className="py-2 flex justify-between">
              <p className="font-medium">{service}</p>
              <p className={`font-semibold ${getStatusColor(status)}`}>
                {status}
              </p>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default HealthStatus;
