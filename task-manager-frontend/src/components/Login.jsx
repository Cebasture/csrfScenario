// src/components/Login.js
import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from "axios";
import validator from "validator"; // Install via: npm install validator
import "./login.css";
const Login = ({ setAuth, setRole }) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errors, setErrors] = useState({}); // State for validation errors
  const navigate = useNavigate();

  // const apiUrl = import.meta.env.VITE_API_URL;
  axios.defaults.baseURL = "/api";
  axios.defaults.withCredentials = true;

  // Sanitization function: Trim and escape basic XSS (simple for client-side)
  const sanitizeInput = (input) => {
    return validator.escape(input.trim()); // Trim and escape HTML entities
  };

  // Validation function
  const validateInputs = () => {
    const newErrors = {};

    // Email validation
    if (!email.trim()) {
      newErrors.email = "Email is required.";
    } else if (!validator.isEmail(email)) {
      newErrors.email = "Please enter a valid email address.";
    }

    // Password validation
    if (!password.trim()) {
      newErrors.password = "Password is required.";
    } else if (password.length < 6) {
      newErrors.password = "Password must be at least 6 characters long.";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0; // Return true if no errors
  };

  const handleSubmit = async (event) => {
    event.preventDefault();

    // Sanitize inputs
    const sanitizedEmail = sanitizeInput(email);
    const sanitizedPassword = sanitizeInput(password);

    // Validate inputs
    if (!validateInputs()) {
      return; // Stop submission if validation fails
    }

    try {
      const response = await axios.post(
        "/login",
        {
          email: sanitizedEmail,
          password: sanitizedPassword,
        },
        {
          withCredentials: true, // Include cookies for session
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      if (response.data.message === "Login successful") {
        console.log(document.cookie);
        // Set authentication and role in App state
        localStorage.setItem("isAuthenticated", "true");
        localStorage.setItem("userRole", response.data.dashboard);
        setAuth(true);
        setRole(response.data.dashboard === "admin" ? "admin" : "user");
        // Redirect based on dashboard type
        const dashboardPath =
          response.data.dashboard === "admin"
            ? "/admin-dashboard"
            : "/dashboard";
        navigate(dashboardPath);
      } else {
        alert(response.data.error);
      }
    } catch (error) {
      console.error("Error:", error);
      alert("An error occurred. Please try again.");
    }
  };

  return (
    <div className="container">
      <h2>Login</h2>
      <form id="loginForm" onSubmit={handleSubmit}>
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
        <div className="input-group">
          <label>Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          {errors.password && <span className="error">{errors.password}</span>}
        </div>
        <button id="login-button" type="submit">
          Login
        </button>
      </form>
      <div className="links">
        <Link to="/forgot-password">Forgot Password?</Link> |
        <Link to="/register">Create Account</Link>
      </div>
    </div>
  );
};

export default Login;
