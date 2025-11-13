import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  fetchUsers,
  updateUserRoles,
  disableUser,
  enableUser,
} from '../services/api'; // Assuming these API calls will be added
import { useAuth } from '../hooks/useAuth';
import SecurityInsights from './SecurityInsights';
import HealthStatus from './HealthStatus';
import AgentList from './AgentList'; // Import the AgentList component

const AdminDashboard = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { user } = useAuth();

  useEffect(() => {
    if (user && user.role === 'admin') {
      loadUsers();
    } else {
      setError(
        'Access Denied: You must be an administrator to view this page.',
      );
      setLoading(false);
    }
  }, [user]);

  const loadUsers = async () => {
    setLoading(true);
    setError('');
    try {
      const fetchedUsers = await fetchUsers(); // This function needs to be implemented in api.js
      setUsers(fetchedUsers);
    } catch (err) {
      setError(err.message || 'Failed to load users.');
    } finally {
      setLoading(false);
    }
  };

  const handleRoleChange = async (userId, newRole) => {
    try {
      await updateUserRoles(userId, [newRole]); // This function needs to be implemented in api.js
      loadUsers();
    } catch (err) {
      setError(err.message || 'Failed to update user role.');
    }
  };

  const handleDisableUser = async (userId) => {
    if (window.confirm('Are you sure you want to disable this user?')) {
      try {
        await disableUser(userId); // This function needs to be implemented in api.js
        loadUsers();
      } catch (err) {
        setError(err.message || 'Failed to disable user.');
      }
    }
  };

  const handleEnableUser = async (userId) => {
    if (window.confirm('Are you sure you want to enable this user?')) {
      try {
        await enableUser(userId); // This function needs to be implemented in api.js
        loadUsers();
      } catch (err) {
        setError(err.message || 'Failed to enable user.');
      }
    }
  };

  if (loading) {
    return <div className="p-4">Loading users...</div>;
  }

  if (error) {
    return <div className="p-4 text-red-600">Error: {error}</div>;
  }

  return (
    <div className="admin-dashboard-container p-4">
      <h2 className="text-2xl font-bold mb-4">Admin Dashboard</h2>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <SecurityInsights />
        <HealthStatus />
      </div>

      <div className="mt-6">
        <AgentList />
      </div>

      <h3 className="text-xl font-bold mt-6 mb-3">User Management</h3>
      <div className="overflow-x-auto">
        <table className="min-w-full bg-white">
          <thead>
            <tr>
              <th className="py-2 px-4 border-b">ID</th>
              <th className="py-2 px-4 border-b">Username</th>
              <th className="py-2 px-4 border-b">Role</th>
              <th className="py-2 px-4 border-b">2FA Enforced</th>
              <th className="py-2 px-4 border-b">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td className="py-2 px-4 border-b">{u.id}</td>
                <td className="py-2 px-4 border-b">{u.username}</td>
                <td className="py-2 px-4 border-b">
                  <select
                    value={u.role}
                    onChange={(e) => handleRoleChange(u.id, e.target.value)}
                    className="border rounded p-1"
                  >
                    <option value="user">User</option>
                    <option value="analyst">Analyst</option>
                    <option value="admin">Admin</option>
                  </select>
                </td>
                <td className="py-2 px-4 border-b">
                  {u.twofa_enforced ? 'Yes' : 'No'}
                </td>
                <td className="py-2 px-4 border-b">
                  <button
                    onClick={() => handleDisableUser(u.id)}
                    className="bg-red-500 text-white px-3 py-1 rounded mr-2"
                  >
                    Disable
                  </button>
                  <button
                    onClick={() => handleEnableUser(u.id)}
                    className="bg-green-500 text-white px-3 py-1 rounded"
                  >
                    Enable
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3 className="text-xl font-bold mt-6 mb-3">Audit Log</h3>
      <p>View recent system activities and administrative actions.</p>
      <button
        onClick={() => navigate('/admin/audit')}
        className="bg-blue-500 text-white px-4 py-2 rounded"
      >
        View Audit Log
      </button>

      <h3 className="text-xl font-bold mt-6 mb-3">AI Threat Brain</h3>
      <p>Simulate attacks and view AI-powered threat analysis.</p>
      <button
        onClick={() => navigate('/ai-threat-brain')}
        className="bg-purple-500 text-white px-4 py-2 rounded"
      >
        Go to AI Threat Brain
      </button>

      <h3 className="text-xl font-bold mt-6 mb-3">Network Map</h3>
      <p>Visualize the network of PhantomNet agents.</p>
      <button
        onClick={() => navigate('/network-map')}
        className="bg-teal-500 text-white px-4 py-2 rounded"
      >
        View Network Map
      </button>

      <h3 className="text-xl font-bold mt-6 mb-3">Real-Time Attack Map</h3>
      <p>Visualize incoming attacks in real-time on a world map.</p>
      <button
        onClick={() => navigate('/attack-map')}
        className="bg-red-700 text-white px-4 py-2 rounded"
      >
        View Attack Map
      </button>

      <h3 className="text-xl font-bold mt-6 mb-3">Federation Settings</h3>
      <p>Manage agent federation, CA, and bootstrap tokens.</p>
      <button
        onClick={() => navigate('/federation-settings')}
        className="bg-indigo-500 text-white px-4 py-2 rounded"
      >
        Manage Federation
      </button>
    </div>
  );
};

export default AdminDashboard;
