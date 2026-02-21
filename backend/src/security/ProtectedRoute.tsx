import { Navigate } from "react-router-dom";
import { useAuth } from "./AuthContext";

interface Props {
  children: JSX.Element;
  requiredRole?: "admin" | "user";
}

const ProtectedRoute = ({ children, requiredRole }: Props) => {
  const { user } = useAuth();

  if (!user) return <Navigate to="/login" replace />;

  if (requiredRole && user.role !== requiredRole)
    return <Navigate to="/unauthorized" replace />;

  return children;
};

export default ProtectedRoute;