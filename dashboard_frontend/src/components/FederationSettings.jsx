import React, { useState } from 'react';
import { createBootstrapToken } from '../services/api';

const FederationSettings = () => {
  const [bootstrapToken, setBootstrapToken] = useState('');
  const [caFile, setCaFile] = useState(null);

  const handleIssueBootstrapToken = async () => {
    try {
      const res = await createBootstrapToken();
      setBootstrapToken(res.bootstrap_token);
      alert(`New Bootstrap Token: ${res.bootstrap_token}`);
    } catch (error) {
      console.error('Error issuing bootstrap token:', error);
      alert('Failed to issue bootstrap token.');
    }
  };

  const handleCaFileUpload = (event) => {
    setCaFile(event.target.files[0]);
  };

  const handleUploadCa = async () => {
    if (!caFile) {
      alert('Please select a CA file to upload.');
      return;
    }
    try {
      // In a real scenario, this would upload the CA file to the backend.
      // For now, we'll just simulate it.
      console.log('Uploading CA file:', caFile.name);
      alert(`CA file '${caFile.name}' uploaded successfully.`);
      setCaFile(null);
    } catch (error) {
      console.error('Error uploading CA file:', error);
      alert('Failed to upload CA file.');
    }
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-4">Federation Settings</h2>

      <div className="mb-6">
        <h3 className="text-xl font-semibold mb-2">Bootstrap Tokens</h3>
        <button
          onClick={handleIssueBootstrapToken}
          className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
        >
          Issue New Bootstrap Token
        </button>
        {bootstrapToken && (
          <p className="mt-2 text-gray-700">
            Last Issued Token:{' '}
            <span className="font-mono bg-gray-200 p-1 rounded">
              {bootstrapToken}
            </span>
          </p>
        )}
      </div>

      <div className="mb-6">
        <h3 className="text-xl font-semibold mb-2">Node CA Management</h3>
        <input
          type="file"
          accept=".pem,.crt"
          onChange={handleCaFileUpload}
          className="block w-full text-sm text-gray-500
                    file:mr-4 file:py-2 file:px-4
                    file:rounded-full file:border-0
                    file:text-sm file:font-semibold
                    file:bg-violet-50 file:text-violet-700
                    hover:file:bg-violet-100"
        />
        <button
          onClick={handleUploadCa}
          disabled={!caFile}
          className="mt-3 bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600 disabled:opacity-50"
        >
          Upload Node CA Certificate
        </button>
      </div>

      <div>
        <h3 className="text-xl font-semibold mb-2">
          Agent List & Revocation (Placeholder)
        </h3>
        <p className="text-gray-600">
          This section would list registered agents, their certificates, and
          provide options to approve or revoke them.
        </p>
      </div>
    </div>
  );
};

export default FederationSettings;
