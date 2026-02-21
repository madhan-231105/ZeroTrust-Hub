import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/layout/Layout";
import Selection from "./pages/Selection";
import WebAuth from "./pages/WebAuth";
import IdCard from "./pages/IdCard";
import Fingerprint from "./pages/Fingerprint";
import Printer from "./pages/Printer";
import Network from "./pages/Network";

function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Selection />} />
          <Route path="/web" element={<WebAuth />} />
          <Route path="/idcard" element={<IdCard />} />
          <Route path="/fingerprint" element={<Fingerprint />} />
          <Route path="/printer" element={<Printer />} />
          <Route path="/network" element={<Network />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

export default App;