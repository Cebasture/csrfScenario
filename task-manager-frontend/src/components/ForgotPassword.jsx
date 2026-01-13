import React, { useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import validator from "validator"; // For sanitization/validation


const ForgotPassword = () => {
  const [email, setEmail] = useState("");
  const [errors, setErrors] = useState({});

  axios.defaults.baseURL = "/api";
  axios.defaults.withCredentials = true;

  // Sanitization function
  const sanitizeInput = (input) => {
    return validator.escape(input.trim());
  };

  // Validation function
  const validateInputs = () => {
    const newErrors = {};
    if (!email.trim()) {
      newErrors.email = "Email is required.";
    } else if (!validator.isEmail(email)) {
      newErrors.email = "Please enter a valid email address.";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (event) => {
    event.preventDefault();

    // Sanitize and validate inputs
    const sanitizedEmail = sanitizeInput(email);
    if (!validateInputs()) {
      return;
    }

    try {
      const response = await axios.post(
        "/forgot-password",
        {
          email: sanitizedEmail,
        },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      if (response.data.message) {
        alert(response.data.message);
      } else if (response.data.error) {
        alert(response.data.error);
      } else {
        alert("Unexpected response from server.");
      }
    } catch (error) {
      console.error("Error:", error);
      alert("An error occurred. Please try again.");
    }
  };

  return (
    <div className="container">
      <h2>Forgot Password</h2>
      <p>
        Enter your email address and we'll send you a link to reset your
        password.
      </p>
      <form id="forgotPasswordForm" onSubmit={handleSubmit}>
        <div className="input-group">
          <label>Email</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          {errors.email && <span className="error">{errors.email}</span>}
        </div>
        <button type="submit">Send Reset Link</button>
      </form>
      <div className="links">
        <Link to="/login">Back to Login</Link>
      </div>
    </div>
  );
};

export default ForgotPassword;
