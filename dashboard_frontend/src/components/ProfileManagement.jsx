import React, { useState, useEffect } from 'react';
import { useAuth } from '../hooks/useAuth';
import {
  fetchSessions,
  revokeSession,
  revokeAllSessions,
} from '../services/api'; // Import new API functions

const ProfileManagement = () => {
  const { user } = useAuth(); // Assuming useAuth provides user object with username and role
  const [sessions, setSessions] = useState([]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const loadSessions = async () => {
    try {
      const fetchedSessions = await fetchSessions();
      setSessions(fetchedSessions);
    } catch (err) {
      setError(err.message || 'Failed to load sessions.');
    }
  };

  useEffect(() => {
    if (user) {
      loadSessions();
    }
  }, [user]);

  const handleRevokeSession = async (jti) => {
    try {
      await revokeSession(jti);
      setMessage('Session revoked successfully.');
      loadSessions(); // Reload sessions after revocation
    } catch (err) {
      setError(err.message || 'Failed to revoke session.');
    }
  };

  const handleRevokeAllSessions = async () => {
    if (
      window.confirm(
        'Are you sure you want to revoke all other active sessions?',
      )
    ) {
      try {
        await revokeAllSessions(true); // Exclude current session
        setMessage('All other sessions revoked successfully.');
        loadSessions(); // Reload sessions
      } catch (err) {
        setError(err.message || 'Failed to revoke all sessions.');
      }
    }
  };

  if (!user) {
    return (
      <div className="profile-container">
        Please log in to view your profile.
      </div>
    );
  }

  return (
    <div className="profile-container p-4">
      <h2 className="text-2xl font-bold mb-4">User Profile</h2>
      <p>
        <strong>Username:</strong> {user.username}
      </p>
      <p>
        <strong>Role:</strong> {user.role}
      </p>
      {/* Add more profile details or management options here */}

      <h3 className="text-xl font-bold mt-6 mb-3">Active Sessions</h3>
      {message && <p className="text-green-600 mb-2">{message}</p>}
      {error && <p className="text-red-600 mb-2">{error}</p>}

      {sessions.length === 0 ? (
        <p>No active sessions found.</p>
      ) : (
        <ul className="list-disc pl-5">
          {sessions.map((session) => (
            <li key={session.jti} className="mb-2">
              IP: {session.ip || 'N/A'}, User Agent:{' '}
              {session.user_agent || 'N/A'}, Created:{' '}
              {new Date(session.created_at).toLocaleString()}
              <button
                onClick={() => handleRevokeSession(session.jti)}
                className="ml-4 px-3 py-1 bg-red-500 text-white rounded hover:bg-red-600 text-sm"
              >
                Revoke
              </button>
            </li>
          ))}
        </ul>
      )}
      {sessions.length > 0 && (
        <button
          onClick={handleRevokeAllSessions}
          className="mt-4 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700"
        >
          Revoke All Other Sessions
        </button>
      )}

      <h3 className="text-xl font-bold mt-6 mb-3">Change Password</h3>
      <p>
        Password change functionality is now handled via the password reset
        flow.
      </p>
      {/* The old mock button is removed as password reset is now a separate flow */}
    </div>
  );
};

export default ProfileManagement;
