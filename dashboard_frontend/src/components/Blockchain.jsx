import React from 'react';

const Blockchain = ({ blockchain }) => {
  return (
    <div className="blockchain-container">
      <h2>Blockchain Blocks</h2>
      <pre role="complementary">{JSON.stringify(blockchain, null, 2)}</pre>
    </div>
  );
};

export default Blockchain;
