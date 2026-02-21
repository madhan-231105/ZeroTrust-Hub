import { useEffect, useState } from "react";

export default function Header() {
  const [time, setTime] = useState("");

  useEffect(() => {
    const interval = setInterval(() => {
      const now = new Date();
      setTime(now.toTimeString().split(" ")[0]);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-14 px-8 flex items-center justify-between bg-[#0d1117] border-b border-gray-800">
      <h1 className="text-cyan-400 font-bold tracking-widest">
        SECURE-CORE // ACCESS CONTROL
      </h1>
      <span className="font-mono tracking-widest">{time}</span>
    </header>
  );
}