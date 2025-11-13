import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import NetworkMap from './NetworkMap';

jest.mock('../services/api', () => ({
  get: jest.fn(() =>
    Promise.resolve({
      data: [
        {
          id: 1,
          status: 'online',
          role: 'node',
          version: '1.0',
          location: 'US-East',
          last_seen: '2025-11-05T10:00:00Z',
        },
        {
          id: 2,
          status: 'offline',
          role: 'node',
          version: '1.0',
          location: 'US-West',
          last_seen: '2025-11-05T09:00:00Z',
        },
      ],
    }),
  ),
}));

describe('NetworkMap', () => {
  it('renders the network map with a list of agents', async () => {
    render(<NetworkMap />);

    expect(await screen.findByText('Agent Network')).toBeInTheDocument();
    expect(await screen.findByText('US-East')).toBeInTheDocument();
    expect(await screen.findByText('US-West')).toBeInTheDocument();
  });

  it('displays mTLS status and cert expiry placeholders', async () => {
    render(<NetworkMap />);
    expect(await screen.findByText('mTLS Status')).toBeInTheDocument();
    expect(await screen.findByText('Cert Expiry')).toBeInTheDocument();
    expect(await screen.findAllByText('OK')).toHaveLength(2); // For two agents
    expect(await screen.findAllByText('2026-11-05')).toHaveLength(2); // For two agents
  });

  it('displays quick action buttons', async () => {
    render(<NetworkMap />);
    expect(await screen.findByText('Rotate Key')).toBeInTheDocument();
    expect(await screen.findByText('Quarantine')).toBeInTheDocument();
    expect(await screen.findByText('Revoke')).toBeInTheDocument();
  });

  it('triggers alert on Rotate Key button click', async () => {
    const alertMock = jest.spyOn(window, 'alert').mockImplementation(() => {});
    render(<NetworkMap />);
    fireEvent.click(await screen.findByText('Rotate Key'));
    expect(alertMock).toHaveBeenCalledWith('Rotate Key for 1');
    alertMock.mockRestore();
  });
});
