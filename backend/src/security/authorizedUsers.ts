export interface AuthorizedUser {
  id: string;
  email: string;
  password: string;
  role: "admin" | "user";
}

export const authorizedUsers: AuthorizedUser[] = [
  {
    id: "1",
    email: "admin@zerotrust.com",
    password: "Admin@123",
    role: "admin",
  },
  {
    id: "2",
    email: "special@zerotrust.com",
    password: "Special@123",
    role: "user",
  },
];