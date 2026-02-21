import { useNavigate } from "react-router-dom";
import {
  Globe,
  CreditCard,
  Fingerprint,
  Printer,
  Network,
} from "lucide-react";

export default function Selection() {
  const navigate = useNavigate();

  const nodes = [
    {
      title: "Web Login",
      description: "Standard Web Protocol",
      icon: <Globe size={40} />,
      path: "/web",
    },
    {
      title: "ID Card Access",
      description: "RFID / NFC Authentication",
      icon: <CreditCard size={40} />,
      path: "/idcard",
    },
    {
      title: "Fingerprint Scanner",
      description: "Biometric Verification",
      icon: <Fingerprint size={40} />,
      path: "/fingerprint",
    },
    {
      title: "Printer Access",
      description: "Shared Network Service",
      icon: <Printer size={40} />,
      path: "/printer",
    },
    {
      title: "Network Service",
      description: "Custom TCP Test",
      icon: <Network size={40} />,
      path: "/network",
    },
  ];

  return (
    <div>
      <h1 className="text-3xl font-bold mb-10 tracking-widest text-cyan-400">
        Select Authentication Node
      </h1>

      <div className="grid grid-cols-2 md:grid-cols-3 gap-6">
        {nodes.map((node, index) => (
          <div
            key={index}
            onClick={() => navigate(node.path)}
            className="bg-[#161b22] p-8 rounded-xl border border-gray-800 
                       hover:border-cyan-400 hover:shadow-lg hover:shadow-cyan-400/20
                       transition duration-300 cursor-pointer group"
          >
            <div className="text-cyan-400 group-hover:scale-110 transition mb-4">
              {node.icon}
            </div>

            <h3 className="text-lg font-semibold mb-2">
              {node.title}
            </h3>

            <p className="text-sm text-gray-400">
              {node.description}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}