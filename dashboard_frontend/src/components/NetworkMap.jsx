import React, { useState, useEffect } from 'react';
import { getAgents } from '../services/api';

const NetworkMap = () => {
  const [agents, setAgents] = useState([]);
  const [blinkingAgents, setBlinkingAgents] = useState(new Set());
  const [events, setEvents] = useState([]);
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterOrigin, setFilterOrigin] = useState('');
  const [filterAgent, setFilterAgent] = useState('');
  const [filterTopic, setFilterTopic] = useState('');

  useEffect(() => {
    const fetchAgents = async () => {
      try {
        const data = await getAgents();
        setAgents(data);
      } catch (error) {
        console.error('Error fetching agents:', error);
      }
    };

    fetchAgents();

    const ws = new WebSocket('ws://localhost:8000/api/ws/agent-events');

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      const eventData = message.data; // Assuming eventData is nested under 'data' key

      setAgents((prevAgents) =>
        prevAgents.map((agent) =>
          agent.id === eventData.agent_id
            ? {
                ...agent,
                status: eventData.status,
                last_seen: new Date().toISOString(),
              }
            : agent,
        ),
      );
      setBlinkingAgents((prevBlinkingAgents) =>
        new Set(prevBlinkingAgents).add(eventData.agent_id),
      );
      setTimeout(() => {
        setBlinkingAgents((prevBlinkingAgents) => {
          const newBlinkingAgents = new Set(prevBlinkingAgents);
          newBlinkingAgents.delete(eventData.agent_id);
          return newBlinkingAgents;
        });
      }, 2000);

      setEvents((prevEvents) => [eventData, ...prevEvents].slice(0, 50)); // Keep last 50 events
    };

    return () => {
      ws.close();
    };
  }, []);

  const getStatusColor = (status) => {
    if (status === 'online') return 'bg-green-500';
    if (status === 'offline') return 'bg-red-500';
    return 'bg-yellow-500';
  };

  const filteredEvents = events.filter((event) => {
    return (
      (filterSeverity === '' || event.severity === filterSeverity) &&
      (filterOrigin === '' || event.origin === filterOrigin) &&
      (filterAgent === '' || String(event.agent_id) === filterAgent) &&
      (filterTopic === '' || event.topic === filterTopic)
    );
  });

  return (
    <div className="bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-4">Agent Network</h2>
      <table className="min-w-full bg-white">
        <thead>
          <tr>
            <th className="py-2 px-4 border-b">ID</th>
            <th className="py-2 px-4 border-b">Status</th>
            <th className="py-2 px-4 border-b">Role</th>
            <th className="py-2 px-4 border-b">Version</th>
            <th className="py-2 px-4 border-b">Location</th>
            <th className="py-2 px-4 border-b">Last Seen</th>
            <th className="py-2 px-4 border-b">mTLS Status</th>
            <th className="py-2 px-4 border-b">Cert Expiry</th>
            <th className="py-2 px-4 border-b">Actions</th>
          </tr>
        </thead>
        <tbody>
          {agents.map((agent) => (
            <tr key={agent.id}>
              <td className="py-2 px-4 border-b">{agent.id}</td>
              <td className="py-2 px-4 border-b">
                <span
                  className={`inline-block w-3 h-3 rounded-full mr-2 ${getStatusColor(agent.status)} ${blinkingAgents.has(agent.id) ? 'animate-pulse' : ''}`}
                ></span>
                {agent.status}{' '}
                {agent.quarantined && (
                  <span className="text-red-500 font-semibold">
                    (Quarantined)
                  </span>
                )}
              </td>
              <td className="py-2 px-4 border-b">{agent.role}</td>
              <td className="py-2 px-4 border-b">{agent.version}</td>
              <td className="py-2 px-4 border-b">{agent.location}</td>
              <td className="py-2 px-4 border-b">
                {new Date(agent.last_seen).toLocaleString()}
              </td>
              <td className="py-2 px-4 border-b">OK</td> {/* Placeholder */}
              <td className="py-2 px-4 border-b">2026-11-05</td>{' '}
              {/* Placeholder */}
              <td className="py-2 px-4 border-b">
                {agent.quarantined && (
                  <button
                    onClick={() => alert(`Approve Agent ${agent.id}`)}
                    className="bg-green-500 text-white px-2 py-1 rounded text-sm mr-2"
                  >
                    Approve
                  </button>
                )}
                <button
                  onClick={() => alert(`Rotate Key for ${agent.id}`)}
                  className="bg-yellow-500 text-white px-2 py-1 rounded text-sm mr-2"
                >
                  Rotate Key
                </button>
                <button
                  onClick={() => alert(`Quarantine ${agent.id}`)}
                  className="bg-orange-500 text-white px-2 py-1 rounded text-sm mr-2"
                >
                  Quarantine
                </button>
                <button
                  onClick={() => alert(`Revoke ${agent.id}`)}
                  className="bg-red-500 text-white px-2 py-1 rounded text-sm"
                >
                  Revoke
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 className="text-2xl font-bold mt-8 mb-4">Live Events Feed</h2>
      <div className="flex space-x-4 mb-4">
        <input
          type="text"
          placeholder="Filter by Severity"
          className="border p-2 rounded"
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
        />
        <input
          type="text"
          placeholder="Filter by Origin"
          className="border p-2 rounded"
          value={filterOrigin}
          onChange={(e) => setFilterOrigin(e.target.value)}
        />
        <input
          type="text"
          placeholder="Filter by Agent ID"
          className="border p-2 rounded"
          value={filterAgent}
          onChange={(e) => setFilterAgent(e.target.value)}
        />
        <input
          type="text"
          placeholder="Filter by Topic"
          className="border p-2 rounded"
          value={filterTopic}
          onChange={(e) => setFilterTopic(e.target.value)}
        />
      </div>
      <div className="bg-gray-100 p-4 rounded-lg h-64 overflow-y-scroll">
        {filteredEvents.length === 0 ? (
          <p className="text-gray-500">No events to display.</p>
        ) : (
          filteredEvents.map((event, index) => (
            <div
              key={index}
              className="mb-2 p-2 border-b border-gray-300 last:border-b-0"
            >
              <p className="text-sm font-semibold">
                [{new Date(event.timestamp).toLocaleTimeString()}]{' '}
                <span className="font-normal">
                  Agent {event.agent_id} - {event.status}
                </span>
              </p>
              {/* Render other event details as needed */}
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default NetworkMap;
