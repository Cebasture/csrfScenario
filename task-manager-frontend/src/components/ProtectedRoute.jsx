// src/components/ProtectedRoute.js
import { Navigate } from "react-router-dom";

const ProtectedRoute = ({
  isAuthenticated,
  requiredRole,
  userRole,
  children,
}) => {
  console.log(
    "ProtectedRoute check - auth:",
    isAuthenticated,
    "role:",
    userRole,
    "required:",
    requiredRole
  );
  if (!isAuthenticated) {
    return <Navigate to="/login" />;
  }
  if (requiredRole && userRole !== requiredRole) {
    // Redirect non-admins to user dashboard, or handle as needed
    return <Navigate to="/dashboard" />;
  }
  return children;
};

export default ProtectedRoute;
