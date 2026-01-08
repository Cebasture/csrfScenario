// src/components/ResetPassword.jsx
import React, { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import axios from 'axios';
import validator from 'validator';
import './ResetPassword.css';

const ResetPassword = () => {
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errors, setErrors] = useState({});
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const token = searchParams.get('token');
  // const apiUrl = import.meta.env.VITE_API_URL;
  axios.defaults.baseURL = "/api";
  axios.defaults.withCredentials = true;

  const sanitizeInput = (input) => {
    return validator.escape(input.trim());
  };

  const validateInputs = () => {
    const newErrors = {};

    if (!newPassword.trim()) {
      newErrors.newPassword = 'New password is required.';
    } else if (newPassword.length < 6) {
      newErrors.newPassword = 'Password must be at least 6 characters long.';
    }

    if (!confirmPassword.trim()) {
      newErrors.confirmPassword = 'Please confirm your password.';
    } else if (newPassword !== confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match.';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    const sanitizedPassword = sanitizeInput(newPassword);

    if (!validateInputs()) return;

    try {
      await axios.post("/reset-password", {
        token,
        newPassword: sanitizedPassword,
      });

      alert('Password reset successful. Please login.');
      navigate('/login');
    } catch (err) {
      console.error(err);
      alert('Invalid or expired reset link.');
    }
  };

  return (
    <div className="container">
      <h2>Reset Password</h2>
      <form id="resetForm" onSubmit={handleSubmit}>
        <div className="input-group">
          <label>New Password</label>
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
          />
          {errors.newPassword && <span className="error">{errors.newPassword}</span>}
        </div>

        <div className="input-group">
          <label>Confirm Password</label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
          {errors.confirmPassword && (
            <span className="error">{errors.confirmPassword}</span>
          )}
        </div>

        <button type="submit">Reset Password</button>
      </form>
    </div>
  );
};

export default ResetPassword;