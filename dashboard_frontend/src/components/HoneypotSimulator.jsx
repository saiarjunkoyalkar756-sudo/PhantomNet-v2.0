import React, { useState } from 'react';
import { simulateHoneypotControl, simulateAttack } from '../services/api';
import { toast } from 'react-toastify';

const HoneypotSimulator = () => {
  const [port, setPort] = useState('');
  const [attackIp, setAttackIp] = useState('');
  const [attackData, setAttackData] = useState('');
  const [loading, setLoading] = useState(false);

  const handleHoneypotControl = async (action) => {
    setLoading(true);
    try {
      const response = await simulateHoneypotControl(action, parseInt(port));
      toast.success(response.message);
    } catch (error) {
      toast.error(`Error: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleSimulateAttack = async () => {
    setLoading(true);
    try {
      const response = await simulateAttack(
        attackIp,
        parseInt(port),
        attackData,
      );
      toast.success(response.message);
    } catch (error) {
      toast.error(`Error: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="honeypot-simulator-container">
      <h2>Honeypot Simulator</h2>

      <div className="control-section">
        <h3>Honeypot Control (Mock)</h3>
        <input
          type="number"
          value={port}
          onChange={(e) => setPort(e.target.value)}
          placeholder="Port (e.g., 2222)"
          min="1"
          max="65535"
        />
        <button
          onClick={() => handleHoneypotControl('start')}
          disabled={loading || !port}
        >
          Start Honeypot
        </button>
        <button
          onClick={() => handleHoneypotControl('stop')}
          disabled={loading || !port}
        >
          Stop Honeypot
        </button>
      </div>

      <div className="simulate-attack-section">
        <h3>Simulate Attack</h3>
        <input
          type="text"
          value={attackIp}
          onChange={(e) => setAttackIp(e.target.value)}
          placeholder="Attacker IP (e.g., 192.168.1.1)"
        />
        <input
          type="number"
          value={port}
          onChange={(e) => setPort(e.target.value)}
          placeholder="Target Port (e.g., 2222)"
          min="1"
          max="65535"
        />
        <textarea
          value={attackData}
          onChange={(e) => setAttackData(e.target.value)}
          placeholder="Attack Data (e.g., SQL injection payload)"
          rows="4"
        ></textarea>
        <button
          onClick={handleSimulateAttack}
          disabled={loading || !attackIp || !port || !attackData}
        >
          Simulate Attack
        </button>
      </div>
    </div>
  );
};

export default HoneypotSimulator;
