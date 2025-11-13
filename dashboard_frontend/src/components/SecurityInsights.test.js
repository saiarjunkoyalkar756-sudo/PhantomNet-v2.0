import React from 'react';
import { render, screen } from '@testing-library/react';
import SecurityInsights from './SecurityInsights';

jest.mock('../services/api', () => ({
  get: jest.fn((url) => {
    if (url === '/security/trust-metrics') {
      return Promise.resolve({ data: { trust_score: 85 } });
    }
    if (url === '/security/alerts') {
      return Promise.resolve({
        data: [
          {
            timestamp: '2025-11-05T10:00:00Z',
            message: 'Anomaly detected',
            risk_level: 'High',
          },
          {
            timestamp: '2025-11-05T09:00:00Z',
            message: 'Failed login',
            risk_level: 'Medium',
          },
        ],
      });
    }
    if (url === '/sessions') {
      return Promise.resolve({
        data: [
          { ip: '192.168.1.1', user_agent: 'Chrome' },
          { ip: '192.168.1.2', user_agent: 'Firefox' },
        ],
      });
    }
  }),
}));

describe('SecurityInsights', () => {
  it('renders the trust score, alerts, and sessions', async () => {
    render(<SecurityInsights />);

    expect(await screen.findByText('85.0')).toBeInTheDocument();
    expect(await screen.findByText('Anomaly detected')).toBeInTheDocument();
    expect(await screen.findByText('IP: 192.168.1.1')).toBeInTheDocument();
  });
});
