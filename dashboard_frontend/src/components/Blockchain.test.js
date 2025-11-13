import { render, screen } from '@testing-library/react';
import Blockchain from './Blockchain';

describe('Blockchain Component', () => {
  it('should render blockchain data correctly', () => {
    const mockBlockchain = [
      {
        index: 1,
        timestamp: 1672531200,
        transactions: [],
        proof: 100,
        previous_hash: '1',
      },
      {
        index: 2,
        timestamp: 1672534800,
        transactions: ['tx1'],
        proof: 200,
        previous_hash: 'a',
      },
    ];

    render(<Blockchain blockchain={mockBlockchain} />);

    const preElement = screen.getByRole('complementary');
    const receivedJson = JSON.parse(preElement.textContent);
    expect(receivedJson).toEqual(mockBlockchain);
  });

  it('should render an empty pre tag if there is no blockchain data', () => {
    render(<Blockchain blockchain={[]} />);

    const code = screen.getByText('[]');
    expect(code).toBeInTheDocument();
  });
});
