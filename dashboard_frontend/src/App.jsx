import React, { useState, useEffect } from 'react';
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  Link,
} from 'react-router-dom';
import LoginPage from './components/LoginPage';
import TwoFactorAuthSetup from './components/TwoFactorAuthSetup'; // Import the new component
import PasswordResetRequestPage from './components/PasswordResetRequestPage'; // Import new component
import PasswordResetConfirmPage from './components/PasswordResetConfirmPage'; // Import new component
import AdminDashboard from './components/AdminDashboard'; // Import AdminDashboard
import AuditLogViewer from './components/AuditLogViewer'; // Import AuditLogViewer
import AIThreatBrain from './components/AIThreatBrain'; // Import AIThreatBrain
import NetworkMap from './components/NetworkMap'; // Import NetworkMap
import FederationSettings from './components/FederationSettings'; // Import FederationSettings
import AttackMapPage from './components/AttackMapPage'; // Import AttackMapPage
import BlockchainViewer from './components/BlockchainViewer'; // Import BlockchainViewer
import { getMe } from './services/auth'; // Assuming getMe is still used for user data
import { logout, login } from './services/api'; // Import logout and login from api.js
import './App.css';

import SecurityInsightsCard from './components/SecurityInsightsCard'; // Import the new component
import HealthStatusWidget from './components/HealthStatusWidget'; // Import the new component
import SecurityAlerts from './components/SecurityAlerts'; // Import the new SecurityAlerts component

const Dashboard = ({ user, onLogout }) => {
  return (
    <div className="min-h-screen bg-gray-100 flex flex-col items-center justify-center">
      <h1 className="text-4xl font-bold text-gray-800 mb-4">
        Welcome to the Dashboard, {user.username}!
      </h1>
      <p className="text-lg text-gray-600">Your role: {user.role}</p>
      <p className="text-lg text-gray-600">
        2FA Enabled: {user.twofa_enabled ? 'Yes' : 'No'}
      </p>
      <p className="text-lg text-gray-600">
        2FA Enforced: {user.twofa_enforced ? 'Yes' : 'No'}
      </p>
      <Link
        to="/2fa-setup"
        className="mt-4 px-6 py-3 bg-blue-600 text-white rounded-md shadow-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
      >
        Manage 2FA
      </Link>
      {user.role === 'admin' && (
        <Link
          to="/admin"
          className="mt-4 px-6 py-3 bg-purple-600 text-white rounded-md shadow-md hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500"
        >
          Admin Dashboard
        </Link>
      )}
      {user.role === 'admin' && (
        <Link
          to="/blockchain"
          className="mt-4 px-6 py-3 bg-green-600 text-white rounded-md shadow-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
        >
          View Blockchain
        </Link>
      )}
      <div className="mt-8 w-full max-w-4xl grid grid-cols-1 md:grid-cols-2 gap-4">
        {' '}
        {/* Modified container for the new cards */}
        <SecurityInsightsCard />
        <HealthStatusWidget />
        <div className="md:col-span-2">
          <SecurityAlerts />
        </div>
      </div>
      <button
        onClick={onLogout}
        className="mt-8 px-6 py-3 bg-red-600 text-white rounded-md shadow-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
      >
        Logout
      </button>
    </div>
  );
};

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchUser = async () => {
    try {
      const userData = await getMe();
      setUser(userData);
    } catch (error) {
      console.error('Failed to fetch user data:', error);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUser();
  }, []);

  const handleLoginSuccess = () => {
    fetchUser(); // Re-fetch user data after successful login (cookie is set)
  };

  const handleLogout = async () => {
    try {
      await logout(); // Use the logout function from api.js
      setUser(null);
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-xl">
        Loading...
      </div>
    );
  }

  return (
    <Router>
      <Routes>
        <Route
          path="/login"
          element={
            user ? (
              <Navigate to="/dashboard" />
            ) : (
              <LoginPage setToken={handleLoginSuccess} />
            )
          }
        />
        <Route
          path="/dashboard"
          element={
            user ? (
              <Dashboard user={user} onLogout={handleLogout} />
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="/2fa-setup"
          element={user ? <TwoFactorAuthSetup /> : <Navigate to="/login" />}
        />
        {/* New routes for password reset */}
        <Route
          path="/request-password-reset"
          element={<PasswordResetRequestPage />}
        />
        <Route path="/reset-password" element={<PasswordResetConfirmPage />} />
        <Route
          path="/admin"
          element={
            user && user.role === 'admin' ? (
              <AdminDashboard />
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="/admin/audit"
          element={
            user && user.role === 'admin' ? (
              <AuditLogViewer />
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="/ai-threat-brain"
          element={
            user && user.role === 'admin' ? (
              <AIThreatBrain />
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="/network-map"
          element={
            user && user.role === 'admin' ? (
              <NetworkMap />
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="/attack-map"
          element={
            user && user.role === 'admin' ? (
              <AttackMapPage />
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="/federation-settings"
          element={
            user && user.role === 'admin' ? (
              <FederationSettings />
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="/blockchain"
          element={
            user && user.role === 'admin' ? (
              <BlockchainViewer />
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="*"
          element={<Navigate to={user ? '/dashboard' : '/login'} />}
        />
      </Routes>
    </Router>
  );
}

export default App;
