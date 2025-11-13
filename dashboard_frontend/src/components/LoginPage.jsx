import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login, resolve2FaChallenge } from '../services/api'; // Import resolve2FaChallenge

const LoginPage = ({ setToken }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState(''); // New state for recovery code
  const [error, setError] = useState('');
  const [twoFaRequired, setTwoFaRequired] = useState(false);
  const [challengeId, setChallengeId] = useState(null); // New state for challenge ID
  const [useRecoveryCode, setUseRecoveryCode] = useState(false); // New state to toggle between TOTP and recovery code
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    try {
      let data;
      if (twoFaRequired && challengeId) {
        // If 2FA is required and we have a challenge ID, resolve the challenge
        data = await resolve2FaChallenge(
          challengeId,
          useRecoveryCode ? null : totpCode,
          useRecoveryCode ? recoveryCode : null,
        );
      } else {
        // Otherwise, attempt initial login
        data = await login(username, password);
      }

      if (data.mfa_required) {
        setTwoFaRequired(true);
        setChallengeId(data.challenge_id);
        setError(
          'Two-factor authentication is required. Please enter your TOTP code or a recovery code.',
        );
      } else {
        // Successful login or 2FA challenge resolution
        setToken(data.access_token);
        navigate('/dashboard');
      }
    } catch (err) {
      setError(err.message || 'Login failed');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Sign in to your account
          </h2>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <input type="hidden" name="remember" value="true" />
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            {twoFaRequired && (
              <div className="mt-4">
                {useRecoveryCode ? (
                  <input
                    id="recovery_code"
                    name="recovery_code"
                    type="text"
                    autoComplete="off"
                    required
                    className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                    placeholder="Recovery Code"
                    value={recoveryCode}
                    onChange={(e) => setRecoveryCode(e.target.value)}
                  />
                ) : (
                  <input
                    id="totp_code"
                    name="totp_code"
                    type="text"
                    autoComplete="one-time-code"
                    required
                    className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                    placeholder="TOTP Code"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value)}
                  />
                )}
                <button
                  type="button"
                  onClick={() => setUseRecoveryCode(!useRecoveryCode)}
                  className="mt-2 text-sm text-indigo-600 hover:text-indigo-500"
                >
                  {useRecoveryCode
                    ? 'Use TOTP Code'
                    : 'Use Recovery Code Instead'}
                </button>
              </div>
            )}
          </div>

          {error && (
            <p className="mt-2 text-center text-sm text-red-600">{error}</p>
          )}

          <div>
            <button
              type="submit"
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
            >
              Sign in
            </button>
          </div>
          <div className="text-sm text-center">
            <a
              href="/request-password-reset"
              className="font-medium text-indigo-600 hover:text-indigo-500"
            >
              Forgot your password?
            </a>
          </div>
        </form>
      </div>
    </div>
  );
};

export default LoginPage;
