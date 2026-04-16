import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { projectsApi, api } from "../utils/api";
import type { Project } from "../types";

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data: project, isLoading } = useQuery<Project>({
    queryKey: ["project", id],
    queryFn: () => projectsApi.get(id!),
  });

  const { data: summary } = useQuery({
    queryKey: ["findings-summary", id],
    queryFn: () => api.get(`/findings/project/${id}/summary`).then(r => r.data),
    enabled: !!id,
  });

  if (isLoading) return <div style={{ padding: "2rem", color: "#6b7280" }}>Loading…</div>;
  if (!project) return <div style={{ padding: "2rem", color: "#ef4444" }}>Project not found.</div>;

  const statusColors: Record<string, string> = {
    "Open": "#fee2e2", "Not a Finding": "#dcfce7",
    "Not Applicable": "#f3f4f6", "Not Reviewed": "#fef9c3",
  };

  return (
    <div style={{ padding: "2rem", maxWidth: 960 }}>
      <button onClick={() => navigate("/")} style={backBtn}>← Projects</button>
      <h1 style={{ margin: "0.5rem 0 0.25rem", fontSize: 22, fontWeight: 600 }}>{project.name}</h1>
      {project.system_name && <p style={{ margin: "0 0 1.5rem", color: "#6b7280", fontSize: 14 }}>{project.system_name}</p>}

      {summary && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: "1.5rem" }}>
          <StatCard label="Total Findings" value={summary.total} color="#dbeafe" />
          {Object.entries(summary.by_status || {}).map(([k, v]) => (
            <StatCard key={k} label={k} value={v as number} color={statusColors[k] || "#f3f4f6"} />
          ))}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: "2rem" }}>
        <ModuleCard
          title="Consolidate Scans"
          desc="Import .fpr, .csv, .xlsx files and merge findings"
          action={() => navigate(`/projects/${id}/consolidate`)}
          icon="📥"
        />
        <ModuleCard
          title="STIG Checklist"
          desc="Export ASD STIG .ckl and XCCDF XML"
          action={() => navigate(`/projects/${id}/stig`)}
          icon="🛡️"
        />
        <ModuleCard
          title="ZAP → CCI Mapper"
          desc="Map OWASP ZAP alerts to CCIs for eMASS"
          action={() => navigate(`/projects/${id}/zap`)}
          icon="🔗"
        />
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: "1rem", alignItems: "center" }}>
        <h2 style={{ margin: 0, fontSize: 17, fontWeight: 600 }}>Findings</h2>
        <a href={`/api/export/consolidated/${id}`}
          style={{ marginLeft: "auto", ...downloadBtn }}>
          ⬇ Download Excel
        </a>
      </div>
      <FindingsTable projectId={id!} />
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ background: color, borderRadius: 8, padding: "0.875rem 1rem" }}>
      <div style={{ fontSize: 11, color: "#6b7280", fontWeight: 500, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 700 }}>{value}</div>
    </div>
  );
}

function ModuleCard({ title, desc, action, icon }: { title: string; desc: string; action: () => void; icon: string }) {
  return (
    <div onClick={action} style={{
      background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10,
      padding: "1.25rem", cursor: "pointer", transition: "border-color 0.15s",
    }}
      onMouseEnter={e => (e.currentTarget.style.borderColor = "#3b82f6")}
      onMouseLeave={e => (e.currentTarget.style.borderColor = "#e5e7eb")}>
      <div style={{ fontSize: 24, marginBottom: 8 }}>{icon}</div>
      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}>{title}</div>
      <div style={{ fontSize: 13, color: "#6b7280" }}>{desc}</div>
    </div>
  );
}

function FindingsTable({ projectId }: { projectId: string }) {
  const { data: findings = [], isLoading } = useQuery({
    queryKey: ["findings", projectId],
    queryFn: () => api.get(`/findings/project/${projectId}`).then(r => r.data),
  });

  if (isLoading) return <p style={{ color: "#6b7280" }}>Loading findings…</p>;
  if (!findings.length) return (
    <div style={{ background: "#f9fafb", border: "1px dashed #d1d5db", borderRadius: 8, padding: "2rem", textAlign: "center", color: "#6b7280" }}>
      No findings yet. Import a scan file using Consolidate Scans.
    </div>
  );

  const sevColor: Record<string, string> = {
    critical: "#fef2f2", high: "#fff1f2", medium: "#fffbeb", low: "#f0fdf4", informational: "#f9fafb",
  };

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr style={{ background: "#1e3a5f", color: "#fff" }}>
            {["Tool", "Severity", "Title", "CWE", "Status", "Justification"].map(h => (
              <th key={h} style={{ padding: "10px 12px", textAlign: "left", fontWeight: 500 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {findings.map((f: any, i: number) => (
            <tr key={f.id} style={{ background: i % 2 === 0 ? "#fff" : "#f9fafb", borderBottom: "1px solid #e5e7eb" }}>
              <td style={{ padding: "8px 12px" }}><span style={toolBadge(f.source_tool)}>{f.source_tool}</span></td>
              <td style={{ padding: "8px 12px", background: sevColor[(f.severity || "").toLowerCase()] || "" }}>
                {f.severity || "—"}
              </td>
              <td style={{ padding: "8px 12px", maxWidth: 280 }}>{f.title || "—"}</td>
              <td style={{ padding: "8px 12px", color: "#6b7280" }}>{f.cwe_id || "—"}</td>
              <td style={{ padding: "8px 12px" }}>
                <span style={statusBadge(f.status)}>{f.status}</span>
              </td>
              <td style={{ padding: "8px 12px", color: "#6b7280", maxWidth: 200, fontSize: 12 }}>
                {f.justification || <span style={{ color: "#d1d5db" }}>—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const toolBadge = (tool: string): React.CSSProperties => ({
  background: tool === "fortify" ? "#ede9fe" : "#e0f2fe",
  color: tool === "fortify" ? "#5b21b6" : "#0369a1",
  padding: "2px 8px", borderRadius: 99, fontSize: 11, fontWeight: 500,
});

const statusBadge = (status: string): React.CSSProperties => {
  const map: Record<string, [string, string]> = {
    "Open": ["#fee2e2", "#b91c1c"],
    "Not a Finding": ["#dcfce7", "#15803d"],
    "Not Applicable": ["#f3f4f6", "#374151"],
    "Not Reviewed": ["#fef9c3", "#92400e"],
  };
  const [bg, color] = map[status] || ["#f3f4f6", "#374151"];
  return { background: bg, color, padding: "2px 8px", borderRadius: 99, fontSize: 11, fontWeight: 500 };
};

const backBtn: React.CSSProperties = {
  background: "none", border: "none", color: "#6b7280", cursor: "pointer",
  fontSize: 13, padding: 0, marginBottom: 8,
};
const downloadBtn: React.CSSProperties = {
  background: "#059669", color: "#fff", textDecoration: "none",
  borderRadius: 6, padding: "6px 14px", fontSize: 13, fontWeight: 500,
};
