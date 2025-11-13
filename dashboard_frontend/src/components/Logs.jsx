import React from 'react';

const Logs = ({ logs }) => {
  const parseLog = (log) => {
    const parts = log.log.split(' | ');
    const timestamp = parts[0] || '';
    const ip = parts[1]?.split(':')[1] || '';
    const port = parts[2]?.split(':')[1] || '';
    const data = parts[3]?.split(':')[1] || '';
    const location =
      log.location && log.location.city && log.location.country
        ? `${log.location.city}, ${log.location.country}`
        : 'N/A';
    return { timestamp, ip, port, data, location };
  };

  return (
    <div className="log-container">
      <h2>Attack Logs</h2>
      <div className="log-table-container">
        <table className="log-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>IP Address</th>
              <th>Port</th>
              <th>Data</th>
              <th>Location</th>
            </tr>
          </thead>
          <tbody>
            {Array.isArray(logs) &&
              logs.map((log, i) => {
                const { timestamp, ip, port, data, location } = parseLog(log);
                return (
                  <tr key={i} className={log.isNew ? 'new-log-entry' : ''}>
                    <td>{timestamp}</td>
                    <td>{ip}</td>
                    <td>{port}</td>
                    <td>{data}</td>
                    <td>{location}</td>
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Logs;
