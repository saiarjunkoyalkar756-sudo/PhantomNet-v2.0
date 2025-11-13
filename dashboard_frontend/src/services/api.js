const API_BASE_URL = 'https://localhost';

// Helper function to handle API responses
const handleResponse = async (response) => {
  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'API request failed');
  }
  return response.json();
};

// --- Authentication ---
export const login = async (
  username,
  password,
  totpCode = null,
  recoveryCode = null,
) => {
  const payload = {
    username: username,
    password: password,
    totp_code: totpCode,
    recovery_code: recoveryCode,
  };

  const response = await fetch(`${API_BASE_URL}/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (response.status === 403) {
    const errorData = await response.json();
    if (errorData.detail === 'Two-factor authentication is required.') {
      throw new Error('2FA_REQUIRED');
    }
  }

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'Login failed');
  }

  return response.json();
};

export const logout = async () => {
  const response = await fetch(`${API_BASE_URL}/logout`, {
    method: 'POST',
  });
  return handleResponse(response);
};

export const requestPasswordReset = async (username) => {
  const response = await fetch(`${API_BASE_URL}/password-reset/request`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username }),
  });
  return handleResponse(response);
};

export const resetPassword = async (token, new_password) => {
  const response = await fetch(`${API_BASE_URL}/password-reset/reset`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ token, new_password }),
  });
  return handleResponse(response);
};

export const resolve2FaChallenge = async (
  challenge_id,
  code = null,
  recovery_code = null,
) => {
  const payload = {
    challenge_id: challenge_id,
    code: code,
    recovery_code: recovery_code,
  };
  const response = await fetch(`${API_BASE_URL}/2fa/challenge`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  return handleResponse(response);
};

export const getSessions = async () => {
  const response = await fetch(`${API_BASE_URL}/sessions`);
  return handleResponse(response);
};

// --- Log Management ---
export const getLogs = async () => {
  const response = await fetch(`${API_BASE_URL}/logs`);
  return handleResponse(response);
};

// --- Blockchain ---
export const getBlockchain = async () => {
  const response = await fetch(`${API_BASE_URL}/blockchain`);
  return handleResponse(response);
};

export const verifyBlockchain = async () => {
  const response = await fetch(`${API_BASE_URL}/blockchain/verify`, {
    method: 'POST',
  });
  return handleResponse(response);
};

// --- Security ---
export const getSecurityAlerts = async () => {
  const response = await fetch(`${API_BASE_URL}/security/alerts`);
  return handleResponse(response);
};

export const getTrustMetrics = async () => {
  const response = await fetch(`${API_BASE_URL}/security/trust-metrics`);
  return handleResponse(response);
};

// --- AI & Chatbot ---
export const chatbotQuery = async (query) => {
  const response = await fetch(`${API_BASE_URL}/chatbot`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(query),
  });
  return handleResponse(response);
};

// --- Agents ---
export const getAgents = async () => {
  const response = await fetch(`${API_BASE_URL}/api/agents`);
  return handleResponse(response);
};

export const approveAgent = async (agentId) => {
  const response = await fetch(
    `${API_BASE_URL}/api/agents/${agentId}/approve`,
    {
      method: 'POST',
    },
  );
  return handleResponse(response);
};

export const createBootstrapToken = async () => {
  const response = await fetch(`${API_BASE_URL}/api/agents/bootstrap-token`, {
    method: 'POST',
  });
  return handleResponse(response);
};

// --- Honeypot & Simulation ---
export const simulateAttack = async (attack) => {
  const response = await fetch(`${API_BASE_URL}/honeypot/simulate_attack`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(attack),
  });
  return handleResponse(response);
};

// --- Admin & Config ---
export const getConfig = async () => {
  const response = await fetch(`${API_BASE_URL}/config`);
  return handleResponse(response);
};

export const getIpInfo = async (ipAddress) => {
  const response = await fetch(`${API_BASE_URL}/ip-info/${ipAddress}`);
  return handleResponse(response);
};

// --- Health ---
export const getHealthStatus = async () => {
  const response = await fetch(`${API_BASE_URL}/health`);
  return handleResponse(response);
};

// --- User Management ---
export const fetchUsers = async () => {
  const response = await fetch(`${API_BASE_URL}/api/users`);
  return handleResponse(response);
};

export const updateUserRoles = async (userId, roles) => {
  const response = await fetch(`${API_BASE_URL}/api/users/${userId}/roles`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(roles),
  });
  return handleResponse(response);
};

export const disableUser = async (userId) => {
  const response = await fetch(`${API_BASE_URL}/api/users/${userId}/disable`, {
    method: 'POST',
  });
  return handleResponse(response);
};

export const enableUser = async (userId) => {
  const response = await fetch(`${API_BASE_URL}/api/users/${userId}/enable`, {
    method: 'POST',
  });
  return handleResponse(response);
};

export const fetchAuditLog = async (
  actorId = null,
  eventType = null,
  fromDate = null,
  toDate = null,
) => {
  const params = new URLSearchParams();
  if (actorId) params.append('actor_id', actorId);
  if (eventType) params.append('event_type', eventType);
  if (fromDate) params.append('from_date', fromDate.toISOString());
  if (toDate) params.append('to_date', toDate.toISOString());

  const response = await fetch(
    `${API_BASE_URL}/api/audit-logs?${params.toString()}`,
  );
  return handleResponse(response);
};

// --- Attack Data (Placeholder for now) ---
export const getAttacks = async () => {
  // This endpoint doesn't exist in the backend yet, so return dummy data or an empty array
  return [];
};
