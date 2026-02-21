import { useAuth } from "../../security/AuthContext";

const UserDashboard = () => {
  const { user, logout } = useAuth();

  return (
    <div>
      <h2>User Dashboard</h2>
      <p>Email: {user?.email}</p>
      <p>Trust Score: {user?.trustScore}</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
};

export default UserDashboard;