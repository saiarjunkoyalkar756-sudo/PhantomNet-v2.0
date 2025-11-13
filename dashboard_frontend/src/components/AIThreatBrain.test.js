import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import AIThreatBrain from './AIThreatBrain';

jest.mock('../services/api', () => ({
  post: jest.fn(() =>
    Promise.resolve({
      data: { attack_type: 'sql_injection', confidence: 0.9 },
    }),
  ),
}));

describe('AIThreatBrain', () => {
  it('renders the component and simulates an attack', async () => {
    render(<AIThreatBrain />);

    const textarea = screen.getByPlaceholderText(
      'Enter attack data to simulate...',
    );
    fireEvent.change(textarea, { target: { value: 'SELECT * FROM users' } });

    const simulateButton = screen.getByText('Simulate');
    fireEvent.click(simulateButton);

    expect(
      await screen.findByText('Attack Type: sql_injection'),
    ).toBeInTheDocument();
    expect(await screen.findByText('Confidence: 0.90')).toBeInTheDocument();
  });
});
