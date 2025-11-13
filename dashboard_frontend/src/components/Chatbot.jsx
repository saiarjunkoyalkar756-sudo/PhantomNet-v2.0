import React, { useState } from 'react';
import { fetchChatbotResponse } from '../services/api';

const Chatbot = () => {
  const [query, setQuery] = useState('');
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);

  const handleQuerySubmit = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;

    const userMessage = { sender: 'user', text: query };
    setMessages((prevMessages) => [...prevMessages, userMessage]);
    setLoading(true);
    setQuery('');

    try {
      const response = await fetchChatbotResponse(query);
      const botMessage = { sender: 'bot', text: response.response };
      setMessages((prevMessages) => [...prevMessages, botMessage]);
    } catch (error) {
      console.error('Error fetching chatbot response:', error);
      const errorMessage = {
        sender: 'bot',
        text: 'Error: Could not get a response from the chatbot.',
      };
      setMessages((prevMessages) => [...prevMessages, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="chatbot-container">
      <h2>Chatbot Analyst</h2>
      <div className="chat-window">
        {messages.map((msg, index) => (
          <div key={index} className={`chat-message ${msg.sender}`}>
            <strong>{msg.sender === 'user' ? 'You' : 'Bot'}:</strong> {msg.text}
          </div>
        ))}
        {loading && (
          <div className="chat-message bot">
            <strong>Bot:</strong> Thinking...
          </div>
        )}
      </div>
      <form onSubmit={handleQuerySubmit} className="chat-input-form">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Ask about logs, threats, or blockchain..."
          disabled={loading}
        />
        <button type="submit" disabled={loading}>
          Send
        </button>
      </form>
    </div>
  );
};

export default Chatbot;
