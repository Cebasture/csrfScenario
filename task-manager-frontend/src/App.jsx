import React, { useState, useEffect } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import axios from "axios";
import Login from "./components/Login";
import Register from "./components/Register";
import ForgotPassword from "./components/ForgotPassword";
import Dashboard from "./components/Dashboard";
import AdminDashboard from "./components/AdminDashboard";
import ProtectedRoute from "./components/ProtectedRoute";
import ResetPassword from "./components/ResetPassword";
import "./App.css"; // Optional: Global styles

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userRole, setUserRole] = useState(null); // 'user' or 'admin', set securely from server
  const [loading, setLoading] = useState(true);
  // const apiUrl = import.meta.env.VITE_API_URL;
  axios.defaults.baseURL = "/api";
  axios.defaults.withCredentials = true;


  // Check authentication and role on app load
  const checkAuth = async (userRole) => {
    try {
      const endpoint = userRole === "admin" ? "/adminMe" : "/me";
      const response = await axios.get(endpoint);
      //  const response = await axios.get(`${apiUrl}/me`, { withCredentials: true });
      setIsAuthenticated(true);
      setUserRole(response.data.role); // Ensure /me returns 'role' (see below)
      localStorage.setItem("isAuthenticated", "true");
      localStorage.setItem("userRole", response.data.role || "user");
    } catch (error) {
      setIsAuthenticated(false);
      setUserRole(null);
      localStorage.removeItem("isAuthenticated");
      localStorage.removeItem("userRole");
      console.error("Auth check failed:", error);
    }
  };

  useEffect(() => {
    const init = async () => {
      // Step 1: Load from localStorage as a fast initial state (prevents logout on refresh)
      const storedAuth = localStorage.getItem("isAuthenticated") === "true";
      const storedRole = localStorage.getItem("userRole");
      if (storedAuth) {
        setIsAuthenticated(storedAuth);
        setUserRole(storedRole);
      }
      // Step 2: Validate with server (re-sync state)
      await checkAuth(storedRole);
      // Step 3: Done loading
      setLoading(false);
    };
    init();
  }, []); // Empty dependency array to run once on mount

  if (loading) {
    return <div>Loading...</div>; // Show loading while checking auth
  }

  return (
    <Router>
      <Routes>
        {/* Public Routes */}
        <Route
          path="/login"
          element={<Login setAuth={setIsAuthenticated} setRole={setUserRole} />}
        />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        {/* Protected Routes */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute
              isAuthenticated={isAuthenticated}
              requiredRole="user"
              userRole={userRole}
            >
              <Dashboard
                setIsAuthenticated={setIsAuthenticated}
                setUserRole={setUserRole}
              />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin-dashboard"
          element={
            <ProtectedRoute
              isAuthenticated={isAuthenticated}
              requiredRole="admin"
              userRole={userRole}
            >
              <AdminDashboard
                setIsAuthenticated={setIsAuthenticated}
                setUserRole={setUserRole}
              />
            </ProtectedRoute>
          }
        />
        {/* Default Route: Redirect to login if not authenticated */}
        <Route path="*" element={<Navigate to="/login" />} />
      </Routes>
    </Router>
  );
}

export default App;
