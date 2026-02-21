import { useAuth } from "../security/AuthContext";

const Authorized = () => {
  const { user, logout } = useAuth();

  return (
    <div className="container">
      <div className="sidebar">
        <h2>ZeroTrustHub</h2>
        <ul>
          <li>Dashboard</li>
          <li>Threat Monitor</li>
          <li>Audit Logs</li>
          <li>Settings</li>
        </ul>
      </div>

      <div className="content">
        <h1>Welcome, {user?.email}</h1>

        <div className="card">
          <h3>Trust Score</h3>
          <p
            style={{
              fontSize: "24px",
              color:
                user!.trustScore > 70
                  ? "lightgreen"
                  : user!.trustScore > 40
                  ? "orange"
                  : "red",
            }}
          >
            {user?.trustScore}
          </p>
        </div>

        <div className="card">
          <h3>Access Level</h3>
          <p>{user?.role.toUpperCase()}</p>
        </div>

        <div className="card">
          <h3>System Status</h3>
          <p>All security systems operational.</p>
        </div>

        <button onClick={logout}>Logout</button>
      </div>
    </div>
  );
};

export default Authorized;