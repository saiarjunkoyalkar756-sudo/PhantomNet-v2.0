import { fetchLogs, fetchBlockchain, fetchConfig } from './api';

global.fetch = jest.fn();

const API_BASE_URL = 'http://localhost:8000';

describe('API Service', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('fetchLogs', () => {
    it('should fetch logs successfully', async () => {
      const mockLogs = ['log1', 'log2'];
      fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ logs: mockLogs }),
      });

      const logs = await fetchLogs();

      expect(fetch).toHaveBeenCalledWith(`${API_BASE_URL}/logs`);
      expect(logs).toEqual(mockLogs);
    });

    it('should throw an error if fetching logs fails', async () => {
      fetch.mockResolvedValueOnce({ ok: false });

      await expect(fetchLogs()).rejects.toThrow('Failed to fetch logs');
    });
  });

  describe('fetchBlockchain', () => {
    it('should fetch blockchain data successfully', async () => {
      const mockBlockchain = [{ block: 1 }];
      fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockBlockchain,
      });

      const blockchain = await fetchBlockchain();

      expect(fetch).toHaveBeenCalledWith(`${API_BASE_URL}/blockchain`);
      expect(blockchain).toEqual(mockBlockchain);
    });

    it('should throw an error if fetching blockchain data fails', async () => {
      fetch.mockResolvedValueOnce({ ok: false });

      await expect(fetchBlockchain()).rejects.toThrow(
        'Failed to fetch blockchain data',
      );
    });
  });

  describe('fetchConfig', () => {
    it('should fetch config successfully', async () => {
      const mockConfig = { setting: 'value' };
      fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockConfig,
      });

      const config = await fetchConfig();

      expect(fetch).toHaveBeenCalledWith(`${API_BASE_URL}/config`);
      expect(config).toEqual(mockConfig);
    });

    it('should throw an error if fetching config fails', async () => {
      fetch.mockResolvedValueOnce({ ok: false });

      await expect(fetchConfig()).rejects.toThrow('Failed to fetch config');
    });
  });
});
