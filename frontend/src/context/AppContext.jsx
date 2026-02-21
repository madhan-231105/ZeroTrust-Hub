import { createContext, useState } from "react";

export const AppContext = createContext();

export function AppProvider({ children }) {
  const [state, setState] = useState({
    currentNode: "Selection",
    currentIP: "N/A",
    authStatus: "PENDING",
  });

  return (
    <AppContext.Provider value={{ state, setState }}>
      {children}
    </AppContext.Provider>
  );
}