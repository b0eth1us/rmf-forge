import { Routes, Route } from "react-router-dom";
import Layout from "./components/layout/Layout";
import ProjectsPage from "./pages/ProjectsPage";
import ProjectDetailPage from "./pages/ProjectDetailPage";
import ConsolidatePage from "./pages/ConsolidatePage";
import STIGPage from "./pages/STIGPage";
import ZAPPage from "./pages/ZAPPage";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<ProjectsPage />} />
        <Route path="/projects/:id" element={<ProjectDetailPage />} />
        <Route path="/projects/:id/consolidate" element={<ConsolidatePage />} />
        <Route path="/projects/:id/stig" element={<STIGPage />} />
        <Route path="/projects/:id/zap" element={<ZAPPage />} />
      </Routes>
    </Layout>
  );
}
