import React, { useState, useEffect } from 'react';
import { getAgents, approveAgent } from '../services/api';

const AgentList = () => {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchAgents = async () => {
    try {
      setLoading(true);
      const data = await getAgents();
      setAgents(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleApproveAgent = async (agentId) => {
    try {
      await approveAgent(agentId);
      // Refresh the agent list after approval
      fetchAgents();
    } catch (err) {
      setError(err.message);
    }
  };

  useEffect(() => {
    fetchAgents();
  }, []);

  if (loading) {
    return <div>Loading agent data...</div>;
  }

  if (error) {
    return <div className="text-red-500">Error: {error}</div>;
  }

  return (
    <div className="bg-white shadow-md rounded-lg p-6">
      <h2 className="text-2xl font-bold mb-4">Registered Agents</h2>
      <div className="overflow-x-auto">
        <table className="min-w-full bg-white">
          <thead>
            <tr>
              <th className="py-2">ID</th>
              <th className="py-2">Role</th>
              <th className="py-2">Version</th>
              <th className="py-2">Location</th>
              <th className="py-2">Status</th>
              <th className="py-2">Last Seen</th>
              <th className="py-2">Quarantined</th>
              <th className="py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((agent) => (
              <tr key={agent.id} className="border-b">
                <td className="py-2 text-center">{agent.id}</td>
                <td className="py-2 text-center">{agent.role}</td>
                <td className="py-2 text-center">{agent.version}</td>
                <td className="py-2 text-center">{agent.location}</td>
                <td className="py-2 text-center">{agent.status}</td>
                <td className="py-2 text-center">
                  {new Date(agent.last_seen).toLocaleString()}
                </td>
                <td className="py-2 text-center">
                  {agent.quarantined ? 'Yes' : 'No'}
                </td>
                <td className="py-2 text-center">
                  {agent.quarantined && (
                    <button
                      onClick={() => handleApproveAgent(agent.id)}
                      className="px-4 py-2 bg-green-600 text-white rounded-md shadow-md hover:bg-green-700"
                    >
                      Approve
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AgentList;
