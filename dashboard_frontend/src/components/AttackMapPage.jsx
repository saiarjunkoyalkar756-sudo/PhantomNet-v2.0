import React, { useState, useEffect } from 'react';
import GeoMap from './GeoMap';
import { getAttacks } from '../services/api';

const AttackMapPage = () => {
  const [locations, setLocations] = useState([]);

  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8000/api/ws/agent-events');

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      const eventData = message.data;

      // Assuming the event data contains geolocation information
      if (eventData && eventData.lat && eventData.lon) {
        setLocations((prevLocations) => [...prevLocations, eventData]);
      }
    };

    // Optional: Fetch initial locations
    const fetchInitialData = async () => {
      try {
        const data = await getAttacks(); // Assuming an endpoint for historical attacks
        setLocations(data);
      } catch (error) {
        console.error('Error fetching initial attack data:', error);
      }
    };

    fetchInitialData();

    return () => {
      ws.close();
    };
  }, []);

  return (
    <div className="w-full h-full">
      <h1 className="text-2xl font-bold text-center my-4">
        Real-Time Attack Map
      </h1>
      <GeoMap locations={locations} />
    </div>
  );
};

export default AttackMapPage;
