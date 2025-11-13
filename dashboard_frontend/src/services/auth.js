const API_BASE_URL = 'https://localhost'; // Use HTTPS for the API base URL

export const getMe = async () => {
  const response = await fetch(`${API_BASE_URL}/users/me/`, {
    method: 'GET',
    // The browser will automatically send the HTTP-only cookie
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'Failed to fetch user data');
  }

  return response.json();
};
