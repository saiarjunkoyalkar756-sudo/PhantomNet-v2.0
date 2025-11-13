import React, { useState, useEffect } from 'react';
import { getBlockchain, verifyBlockchain } from '../services/api';

const BlockchainViewer = () => {
  const [blocks, setBlocks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [verificationStatus, setVerificationStatus] = useState(null);

  const fetchBlockchain = async () => {
    try {
      setLoading(true);
      const data = await getBlockchain();
      setBlocks(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyBlockchain = async () => {
    try {
      const data = await verifyBlockchain();
      setVerificationStatus(data.message);
    } catch (err) {
      setVerificationStatus(err.message);
    }
  };

  useEffect(() => {
    fetchBlockchain();
  }, []);

  if (loading) {
    return <div>Loading blockchain data...</div>;
  }

  if (error) {
    return <div className="text-red-500">Error: {error}</div>;
  }

  return (
    <div className="bg-white shadow-md rounded-lg p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-2xl font-bold">Blockchain Viewer</h2>
        <button
          onClick={handleVerifyBlockchain}
          className="px-4 py-2 bg-blue-600 text-white rounded-md shadow-md hover:bg-blue-700"
        >
          Verify Blockchain
        </button>
      </div>
      {verificationStatus && (
        <div className="mb-4 p-4 bg-gray-100 rounded-md">
          <p>{verificationStatus}</p>
        </div>
      )}
      <div className="space-y-4">
        {blocks.map((block) => (
          <div key={block.index} className="border p-4 rounded-md">
            <h3 className="font-bold">Block {block.index}</h3>
            <p className="text-sm text-gray-600">
              Timestamp: {new Date(block.timestamp).toLocaleString()}
            </p>
            <p className="text-sm text-gray-600">
              Previous Hash: {block.previous_hash}
            </p>
            <p className="text-sm text-gray-600">Hash: {block.hash}</p>
            <p className="text-sm text-gray-600">
              Merkle Root: {block.merkle_root}
            </p>
            <details>
              <summary className="cursor-pointer">Data</summary>
              <pre className="bg-gray-100 p-2 rounded-md">
                {JSON.stringify(JSON.parse(block.data), null, 2)}
              </pre>
            </details>
          </div>
        ))}
      </div>
    </div>
  );
};

export default BlockchainViewer;
