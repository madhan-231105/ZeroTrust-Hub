import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from "./security/AuthContext";
import ProtectedRoute from "./security/ProtectedRoute";
import Login from "./features/login/Login";
import AdminDashboard from "./features/dashboard/AdminDashboard";
import UserDashboard from "./features/dashboard/UserDashboard";
import Unauthorized from "./features/Unauthorized";
import HighRisk from "./features/HighRisk";
import Authorized from "./features/Authorized";
import AuthorizedRoute from "./security/AuthorizedRoute";

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Login />} />
          <Route path="/unauthorized" element={<Unauthorized />} />
          <Route path="/high-risk" element={<HighRisk />} />
          <Route
            path="/authorized"
            element={
              <AuthorizedRoute>
                <Authorized />
              </AuthorizedRoute>
            }
          />
          <Route
            path="/admin"
            element={
              <ProtectedRoute requiredRole="admin">
                <AdminDashboard />
              </ProtectedRoute>
            }
          />

          <Route
            path="/dashboard"
            element={
              <ProtectedRoute requiredRole="user">
                <UserDashboard />
              </ProtectedRoute>
            }
          />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;