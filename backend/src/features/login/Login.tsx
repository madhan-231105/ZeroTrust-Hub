import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../security/AuthContext";
import { calculateTrustScore } from "../../security/trustEngine";
import { authorizedUsers } from "../../security/authorizedUsers";

const Login = () => {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [error, setError] = useState("");

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();

    const foundUser = authorizedUsers.find(
      (user) => user.email === email && user.password === password
    );

    if (!foundUser) {
      setFailedAttempts((prev) => prev + 1);
      setError("Invalid credentials. Access Denied.");
      navigate("/unauthorized");
      return;
    }

    const trustScore = calculateTrustScore({
      failedAttempts,
      unusualLocation: false,
      newDevice: false,
      suspiciousTime: false,
    });

    setFailedAttempts(0);
    setError("");

    login(
      {
        id: foundUser.id,
        email: foundUser.email,
        role: foundUser.role,
        trustScore,
      },
      "fake-jwt"
    );

    if (trustScore < 40) {
      navigate("/high-risk");
    } else {
      navigate("/authorized");
    }
  };

  const styles = {
    page: {
      height: "100vh",
      width: "100vw",
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
      background: "linear-gradient(135deg, #0f172a, #0a192f)",
    },
    card: {
      width: "350px",
      padding: "40px",
      borderRadius: "12px",
      backgroundColor: "#1e293b",
      boxShadow: "0 10px 25px rgba(0,0,0,0.4)",
      display: "flex",
      flexDirection: "column" as const,
      gap: "15px",
    },
    title: {
      textAlign: "center" as const,
      color: "#38bdf8",
      marginBottom: "10px",
    },
    error: {
      color: "#f87171",
      fontSize: "14px",
      textAlign: "center" as const,
    },
    input: {
      padding: "12px",
      borderRadius: "8px",
      border: "1px solid #334155",
      backgroundColor: "#0f172a",
      color: "white",
      outline: "none",
    },
    button: {
      padding: "12px",
      borderRadius: "8px",
      border: "none",
      backgroundColor: "#38bdf8",
      color: "#0f172a",
      fontWeight: "bold",
      cursor: "pointer",
    },
  };

  return (
    <div style={styles.page}>
      <form style={styles.card} onSubmit={handleLogin}>
        <h2 style={styles.title}>ZeroTrustHub 🔐</h2>

        {error && <p style={styles.error}>{error}</p>}

        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          style={styles.input}
          required
        />

        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={styles.input}
          required
        />

        <button type="submit" style={styles.button}>
          Secure Login
        </button>
      </form>
    </div>
  );
};

export default Login;