import React, { useState, useEffect } from 'react';
import { fetchAuditLog } from '../services/api';
import { useAuth } from '../hooks/useAuth';

const AuditLogViewer = () => {
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actorId, setActorId] = useState('');
  const [eventType, setEventType] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const { user } = useAuth();

  const loadAuditLogs = async () => {
    setLoading(true);
    setError('');
    try {
      if (user && user.role === 'admin') {
        const logs = await fetchAuditLog(
          actorId ? parseInt(actorId) : null,
          eventType,
          fromDate ? new Date(fromDate) : null,
          toDate ? new Date(toDate) : null,
        );
        setAuditLogs(logs.audit_log || []);
      } else {
        setError(
          'Access Denied: You must be an administrator to view audit logs.',
        );
      }
    } catch (err) {
      setError(err.message || 'Failed to load audit logs.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAuditLogs();
  }, [user, actorId, eventType, fromDate, toDate]); // Reload when filters change

  if (loading) {
    return <div className="p-4">Loading audit logs...</div>;
  }

  if (error) {
    return <div className="p-4 text-red-600">Error: {error}</div>;
  }

  return (
    <div className="audit-log-viewer-container p-4">
      <h2 className="text-2xl font-bold mb-4">Audit Log Viewer</h2>

      <div className="filters mb-4 p-4 border rounded shadow-sm bg-white">
        <h3 className="text-lg font-semibold mb-2">Filters</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <label
              htmlFor="actorId"
              className="block text-sm font-medium text-gray-700"
            >
              Actor ID
            </label>
            <input
              type="number"
              id="actorId"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
              value={actorId}
              onChange={(e) => setActorId(e.target.value)}
            />
          </div>
          <div>
            <label
              htmlFor="eventType"
              className="block text-sm font-medium text-gray-700"
            >
              Event Type
            </label>
            <input
              type="text"
              id="eventType"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
            />
          </div>
          <div>
            <label
              htmlFor="fromDate"
              className="block text-sm font-medium text-gray-700"
            >
              From Date
            </label>
            <input
              type="date"
              id="fromDate"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
              value={fromDate}
              onChange={(e) => setFromDate(e.target.value)}
            />
          </div>
          <div>
            <label
              htmlFor="toDate"
              className="block text-sm font-medium text-gray-700"
            >
              To Date
            </label>
            <input
              type="date"
              id="toDate"
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
              value={toDate}
              onChange={(e) => setToDate(e.target.value)}
            />
          </div>
        </div>
        <button
          onClick={loadAuditLogs}
          className="mt-4 bg-indigo-600 text-white px-4 py-2 rounded-md shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
        >
          Apply Filters
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full bg-white">
          <thead>
            <tr>
              <th className="py-2 px-4 border-b">ID</th>
              <th className="py-2 px-4 border-b">Timestamp</th>
              <th className="py-2 px-4 border-b">Actor ID</th>
              <th className="py-2 px-4 border-b">Event</th>
              <th className="py-2 px-4 border-b">Details</th>
            </tr>
          </thead>
          <tbody>
            {auditLogs.map((log) => (
              <tr key={log.id}>
                <td className="py-2 px-4 border-b">{log.id}</td>
                <td className="py-2 px-4 border-b">
                  {new Date(log.timestamp).toLocaleString()}
                </td>
                <td className="py-2 px-4 border-b">{log.actor_id}</td>
                <td className="py-2 px-4 border-b">{log.event}</td>
                <td className="py-2 px-4 border-b">
                  {JSON.stringify(log.details)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AuditLogViewer;
