import React from 'react';
import { render, screen } from '@testing-library/react';
import HealthStatus from './HealthStatus';

jest.mock('../services/api', () => ({
  get: jest.fn(() =>
    Promise.resolve({
      data: { status: 'Healthy', database: 'Healthy', api_gateway: 'Healthy' },
    }),
  ),
}));

describe('HealthStatus', () => {
  it('renders the health status of the system', async () => {
    render(<HealthStatus />);

    expect(await screen.findByText('System Health')).toBeInTheDocument();
    expect(await screen.findByText('Healthy')).toBeInTheDocument();
  });
});
