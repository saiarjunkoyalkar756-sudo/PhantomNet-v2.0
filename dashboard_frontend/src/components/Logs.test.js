import { render, screen } from '@testing-library/react';
import Logs from './Logs';

describe('Logs Component', () => {
  it('should render logs correctly', () => {
    const mockLogs = [
      '2025-10-31 10:00:00 | IP:192.168.1.1 | Port:12345 | Data:some data',
      '2025-10-31 10:00:01 | IP:192.168.1.2 | Port:54321 | Data:more data',
    ];

    render(<Logs logs={mockLogs} />);

    expect(screen.getByText('2025-10-31 10:00:00')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.1')).toBeInTheDocument();
    expect(screen.getByText('12345')).toBeInTheDocument();
    expect(screen.getByText('some data')).toBeInTheDocument();

    expect(screen.getByText('2025-10-31 10:00:01')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.2')).toBeInTheDocument();
    expect(screen.getByText('54321')).toBeInTheDocument();
    expect(screen.getByText('more data')).toBeInTheDocument();
  });

  it('should render an empty table if there are no logs', () => {
    render(<Logs logs={[]} />);

    const rows = screen.queryAllByRole('row');
    // The header row is still present
    expect(rows).toHaveLength(1);
  });
});
