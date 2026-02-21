import { Navigate } from "react-router-dom";
import { useAuth } from "./AuthContext";

interface Props {
  children: JSX.Element;
}

const allowedEmails = [
  "admin@zerotrust.com",
  "special@zerotrust.com"
];

const AuthorizedRoute = ({ children }: Props) => {
  const { user } = useAuth();

  if (!user) return <Navigate to="/login" />;

  if (!allowedEmails.includes(user.email))
    return <Navigate to="/unauthorized" />;

  return children;
};

export default AuthorizedRoute;