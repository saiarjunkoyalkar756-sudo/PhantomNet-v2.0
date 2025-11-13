import React from 'react';

const Configuration = ({ config }) => {
  return (
    <div className="config-container">
      <h2>Honeypot Configuration</h2>
      <pre role="complementary">{JSON.stringify(config, null, 2)}</pre>
    </div>
  );
};

export default Configuration;
