import { useState, useEffect } from "react";

export default function Sidebar() {
  const [time, setTime] = useState("");
  const [threat, setThreat] = useState("LOW");

  useEffect(() => {
    const interval = setInterval(() => {
      const now = new Date();
      setTime(now.toTimeString().split(" ")[0]);
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  const threatStyles = {
    LOW: "bg-green-400 w-[15%]",
    MEDIUM: "bg-yellow-400 w-[50%]",
    HIGH: "bg-red-500 w-[90%]",
  };

  return (
    <aside className="h-full p-6 space-y-8">
      <div>
        <h2 className="text-xs uppercase tracking-widest text-gray-400 mb-4">
          System Metrics
        </h2>

        <Metric label="Active Node" value="Selection" />
        <Metric label="Assigned IP" value="N/A" />
        <Metric label="Auth Status" value="Pending" />
        <Metric label="Connection" value="Stable" />
      </div>

      <div>
        <h2 className="text-xs uppercase tracking-widest text-gray-400 mb-3">
          Threat Level
        </h2>

        <div className="h-8 bg-gray-800 rounded overflow-hidden relative">
          <div
            className={`h-full transition-all duration-500 ${threatStyles[threat]}`}
          />
        </div>

        <p className="mt-2 font-mono text-sm">{threat}</p>
      </div>

      <div>
        <h2 className="text-xs uppercase tracking-widest text-gray-400 mb-2">
          Timestamp
        </h2>
        <p className="font-mono text-lg">{time}</p>
      </div>
    </aside>
  );
}

function Metric({ label, value }) {
  return (
    <div className="mb-4">
      <p className="text-xs text-gray-400">{label}</p>
      <p className="font-mono text-cyan-400 font-bold">{value}</p>
    </div>
  );
}