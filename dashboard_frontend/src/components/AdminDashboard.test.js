import React from 'react';
import { render, screen } from '@testing-library/react';
import { BrowserRouter as Router } from 'react-router-dom';
import AdminDashboard from './AdminDashboard';
import { useAuth } from '../hooks/useAuth';

import AgentList from './AgentList';

// Mock the useAuth hook
jest.mock('../hooks/useAuth', () => ({
  useAuth: jest.fn(),
}));

// Mock the api services
jest.mock('../services/api', () => ({
  fetchUsers: jest.fn(() => Promise.resolve([])),
  getAgents: jest.fn(() => Promise.resolve([])),
}));

describe('AdminDashboard', () => {
  it('renders the dashboard for admin users', () => {
    // Arrange
    useAuth.mockReturnValue({ user: { role: 'admin' } });

    // Act
    render(
      <Router>
        <AdminDashboard />
      </Router>,
    );

    // Assert
    expect(screen.getByText('Admin Dashboard')).toBeInTheDocument();
    expect(screen.getByText('User Management')).toBeInTheDocument();
    expect(screen.getByText('Registered Agents')).toBeInTheDocument();
  });

  it('shows an access denied message for non-admin users', () => {
    // Arrange
    useAuth.mockReturnValue({ user: { role: 'user' } });

    // Act
    render(
      <Router>
        <AdminDashboard />
      </Router>,
    );

    // Assert
    expect(
      screen.getByText(
        'Access Denied: You must be an administrator to view this page.',
      ),
    ).toBeInTheDocument();
  });
});
