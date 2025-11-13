import { render, screen } from '@testing-library/react';
import Configuration from './Configuration';

describe('Configuration Component', () => {
  it('should render configuration data correctly', () => {
    const mockConfig = {
      honeypot_name: 'PhantomNet',
      port: 8080,
      logging: true,
    };

    render(<Configuration config={mockConfig} />);

    const preElement = screen.getByRole('complementary');
    const receivedJson = JSON.parse(preElement.textContent);
    expect(receivedJson).toEqual(mockConfig);
  });

  it('should render an empty pre tag if there is no configuration data', () => {
    render(<Configuration config={{}} />);

    const code = screen.getByText('{}');
    expect(code).toBeInTheDocument();
  });
});
