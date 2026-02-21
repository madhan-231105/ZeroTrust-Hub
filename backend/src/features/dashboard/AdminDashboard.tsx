import { useAuth } from "../../security/AuthContext";

const AdminDashboard = () => {
  const { user, logout } = useAuth();

  return (
    <div>
      <h2>Admin Dashboard</h2>
      <p>Email: {user?.email}</p>
      <p>Trust Score: {user?.trustScore}</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
};

export default AdminDashboard;