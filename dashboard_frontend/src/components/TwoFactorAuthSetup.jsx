import React, { useState, useEffect } from 'react';
import { QRCodeCanvas } from 'qrcode.react';
import { getMe } from '../services/auth';

const TwoFactorAuthSetup = () => {
  const [user, setUser] = useState(null);
  const [secret, setSecret] = useState('');
  const [otpUri, setOtpUri] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    fetchUser();
  }, []);

  const fetchUser = async () => {
    try {
      const userData = await getMe();
      setUser(userData);
      if (userData.totp_secret) {
        setSecret(userData.totp_secret);
        setOtpUri(generateOtpUri(userData.totp_secret, userData.username));
      }
    } catch (err) {
      console.error('Failed to fetch user data:', err);
      setError('Failed to load user data.');
    }
  };

  const generateOtpUri = (secret, username) => {
    return `otpauth://totp/PhantomNet:${username}?secret=${secret}&issuer=PhantomNet`;
  };

  const handleGenerateSecret = async () => {
    try {
      setError('');
      setMessage('');
      const response = await fetch('https://localhost/2fa/setup/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to generate 2FA secret');
      }
      const data = await response.json();
      setSecret(data.secret);
      setOtpUri(data.otp_uri);
      setMessage('New 2FA secret generated. Scan the QR code and verify.');
    } catch (err) {
      console.error('Error generating 2FA secret:', err);
      setError(err.message || 'Failed to generate 2FA secret.');
    }
  };

  const handleVerifySetup = async () => {
    try {
      setError('');
      setMessage('');
      const response = await fetch('https://localhost/2fa/setup/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code: verificationCode }),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to verify 2FA setup');
      }
      setMessage('2FA successfully enabled!');
      fetchUser(); // Refresh user data
    } catch (err) {
      console.error('Error verifying 2FA setup:', err);
      setError(err.message || 'Failed to verify 2FA setup.');
    }
  };

  const handleDisable2FA = async () => {
    try {
      setError('');
      setMessage('');
      const response = await fetch('https://localhost/2fa/disable', {
        method: 'POST',
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to disable 2FA');
      }
      setMessage('2FA successfully disabled.');
      setSecret('');
      setOtpUri('');
      setVerificationCode('');
      fetchUser(); // Refresh user data
    } catch (err) {
      console.error('Error disabling 2FA:', err);
      setError(err.message || 'Failed to disable 2FA.');
    }
  };

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center text-xl">
        Loading user data...
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Two-Factor Authentication Setup
          </h2>
        </div>

        {message && (
          <p className="mt-2 text-center text-sm text-green-600">{message}</p>
        )}
        {error && (
          <p className="mt-2 text-center text-sm text-red-600">{error}</p>
        )}

        {!user.totp_secret ? (
          <div className="space-y-4">
            <p className="text-center text-gray-600">
              2FA is not currently enabled. Click below to set it up.
            </p>
            <button
              onClick={handleGenerateSecret}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
            >
              Generate 2FA Secret
            </button>

            {secret && otpUri && (
              <div className="mt-4 p-4 border rounded-md bg-white shadow-sm">
                <p className="text-center font-medium">
                  Scan this QR code with your authenticator app:
                </p>
                <div className="flex justify-center my-4">
                  <QRCodeCanvas value={otpUri} size={256} level="H" />
                </div>
                <p className="text-center text-sm text-gray-700">
                  Or enter the secret manually:
                </p>
                <p className="text-center font-mono text-lg break-all">
                  {secret}
                </p>

                <div className="mt-4">
                  <input
                    type="text"
                    placeholder="Enter 6-digit code from app"
                    value={verificationCode}
                    onChange={(e) => setVerificationCode(e.target.value)}
                    className="appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  />
                  <button
                    onClick={handleVerifySetup}
                    className="mt-3 group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
                  >
                    Verify and Enable 2FA
                  </button>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-4">
            <p className="text-center text-gray-600">
              2FA is currently enabled for your account.
            </p>
            <button
              onClick={handleDisable2FA}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
            >
              Disable 2FA
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default TwoFactorAuthSetup;
