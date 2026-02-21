import Header from "./Header";
import Sidebar from "./Sidebar";

export default function Layout({ children }) {
  return (
    <div className="grid grid-cols-[1fr_320px] h-screen bg-[#05070a] text-white">
      <div className="flex flex-col">
        <Header />
        <main className="flex-1 overflow-y-auto p-10">
          {children}
        </main>
      </div>

      <div className="border-l border-gray-800 bg-[#0d1117]">
        <Sidebar />
      </div>
    </div>
  );
}