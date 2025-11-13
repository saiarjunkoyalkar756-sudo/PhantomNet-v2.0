import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import FederationSettings from './FederationSettings';

describe('FederationSettings', () => {
  it('renders the Federation Settings page', () => {
    render(<FederationSettings />);
    expect(screen.getByText('Federation Settings')).toBeInTheDocument();
    expect(screen.getByText('Bootstrap Tokens')).toBeInTheDocument();
    expect(screen.getByText('Node CA Management')).toBeInTheDocument();
  });

  it('issues a new bootstrap token when the button is clicked', async () => {
    render(<FederationSettings />);
    fireEvent.click(screen.getByText('Issue New Bootstrap Token'));
    await waitFor(() => {
      expect(screen.getByText(/Last Issued Token:/)).toBeInTheDocument();
    });
  });

  it('allows uploading a CA file', () => {
    render(<FederationSettings />);
    const file = new File(['dummy content'], 'ca.pem', {
      type: 'application/x-pem-file',
    });
    const input = screen.getByLabelText(/file:mr-4/);
    fireEvent.change(input, { target: { files: [file] } });
    expect(input.files[0]).toBe(file);
    expect(screen.getByText('Upload Node CA Certificate')).not.toBeDisabled();
  });
});
