import React, { useState, useEffect } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  LineChart,
  Line,
} from 'recharts';
import { simulateAttack } from '../services/api';

const AIThreatBrain = () => {
  const [simulations, setSimulations] = useState([]);
  const [simulationData, setSimulationData] = useState('');
  const [attackType, setAttackType] = useState('');
  const [confidence, setConfidence] = useState(0);

  useEffect(() => {
    // Fetch initial data if needed
  }, []);

  const handleSimulateAttack = async () => {
    try {
      const res = await simulateAttack({ data: simulationData });
      setAttackType(res.attack_type);
      setConfidence(res.confidence);
      // Add the new simulation to the list
      setSimulations([
        ...simulations,
        {
          name: `Sim ${simulations.length + 1}`,
          confidence: res.confidence,
          attack_type: res.attack_type,
        },
      ]);
    } catch (error) {
      console.error('Error simulating attack:', error);
    }
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-4">AI Threat Brain</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <h3 className="text-lg font-semibold mb-2">Simulate Attack</h3>
          <textarea
            className="w-full p-2 border rounded"
            rows="4"
            value={simulationData}
            onChange={(e) => setSimulationData(e.target.value)}
            placeholder="Enter attack data to simulate..."
          ></textarea>
          <button
            className="mt-2 bg-blue-500 text-white px-4 py-2 rounded"
            onClick={handleSimulateAttack}
          >
            Simulate
          </button>
          {attackType && (
            <div className="mt-4">
              <p>
                <strong>Attack Type:</strong> {attackType}
              </p>
              <p>
                <strong>Confidence:</strong> {confidence.toFixed(2)}
              </p>
            </div>
          )}
        </div>
        <div>
          <h3 className="text-lg font-semibold mb-2">Threat Scoring</h3>
          <BarChart width={500} height={300} data={simulations}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="confidence" fill="#8884d8" />
          </BarChart>
        </div>
      </div>
      <div className="mt-6">
        <h3 className="text-lg font-semibold mb-2">Threat Evolution</h3>
        <LineChart width={500} height={300} data={simulations}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" />
          <YAxis />
          <Tooltip />
          <Legend />
          <Line type="monotone" dataKey="confidence" stroke="#8884d8" />
        </LineChart>
      </div>
    </div>
  );
};

export default AIThreatBrain;
