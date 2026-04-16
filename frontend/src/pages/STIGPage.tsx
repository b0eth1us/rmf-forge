import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../utils/api";
import type { Finding } from "../types";

export default function STIGPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const { data: findings = [], isLoading } = useQuery<Finding[]>({
    queryKey: ["findings", id],
    queryFn: () => api.get(`/findings/project/${id}`).then(r => r.data),
  });

  const { data: unmapped = [] } = useQuery({
    queryKey: ["unmapped", id],
    queryFn: () => api.get(`/stig/unmapped/${id}`).then(r => r.data),
  });

  const updateMut = useMutation({
    mutationFn: ({ fid, vuln_id }: { fid: string; vuln_id: string }) =>
      api.patch(`/findings/${fid}`, { vuln_id }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings", id] });
      qc.invalidateQueries({ queryKey: ["unmapped", id] });
    },
  });

  if (isLoading) return <div style={{ padding: "2rem", color: "#6b7280" }}>Loading…</div>;

  const mapped = findings.filter(f => f.vuln_id);

  return (
    <div style={{ padding: "2rem", maxWidth: 900 }}>
      <button onClick={() => navigate(`/projects/${id}`)} style={backBtn}>← Project</button>
      <h1 style={{ margin: "0.5rem 0 0.25rem", fontSize: 22, fontWeight: 600 }}>ASD STIG Checklist Export</h1>
      <p style={{ margin: "0 0 1.5rem", color: "#6b7280", fontSize: 14 }}>
        Application Security and Development STIG — review mappings then export .ckl or XCCDF
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: "1.5rem" }}>
        <StatCard label="Total findings" value={findings.length} color="#dbeafe" />
        <StatCard label="Mapped to STIG Vuln ID" value={mapped.length} color="#dcfce7" />
      </div>

      {unmapped.length > 0 && (
        <div style={{ background: "#fffbeb", border: "1px solid #fcd34d", borderRadius: 8, padding: "1rem", marginBottom: "1.5rem" }}>
          <strong style={{ fontSize: 14 }}>⚠️ {unmapped.length} unmapped findings</strong>
          <p style={{ margin: "6px 0 0", fontSize: 13, color: "#6b7280" }}>
            These have no ASD STIG Vuln ID. Assign one below before exporting, or they will export as placeholder V-222400.
          </p>
          <table style={{ width: "100%", borderCollapse: "collapse", marginTop: 10, fontSize: 13 }}>
            <thead>
              <tr style={{ background: "#92400e", color: "#fff" }}>
                {["Title", "Tool", "Assign Vuln ID"].map(h => (
                  <th key={h} style={{ padding: "7px 10px", textAlign: "left", fontWeight: 500 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {unmapped.map((f: any) => (
                <tr key={f.id} style={{ borderBottom: "1px solid #fde68a" }}>
                  <td style={{ padding: "6px 10px" }}>{f.title || "—"}</td>
                  <td style={{ padding: "6px 10px", color: "#6b7280" }}>{f.source_tool}</td>
                  <td style={{ padding: "6px 10px" }}>
                    <input
                      placeholder="e.g. V-222604"
                      style={{ border: "1px solid #d1d5db", borderRadius: 5, padding: "4px 8px", fontSize: 13, width: 130 }}
                      onBlur={e => { if (e.target.value) updateMut.mutate({ fid: f.id, vuln_id: e.target.value }); }}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div style={{ display: "flex", gap: 10, marginBottom: "1.5rem" }}>
        <a href={`/api/stig/export/ckl/${id}`} style={{ ...dlBtn, background: "#1d4ed8" }}>
          ⬇ Download STIG Viewer .ckl
        </a>
        <a href={`/api/stig/export/xccdf/${id}`} style={{ ...dlBtn, background: "#059669" }}>
          ⬇ Download XCCDF XML
        </a>
      </div>

      <h2 style={{ fontSize: 16, fontWeight: 600, margin: "0 0 0.75rem" }}>All findings with Vuln ID</h2>
      {mapped.length === 0 ? (
        <p style={{ color: "#6b7280", fontSize: 14 }}>No findings mapped to Vuln IDs yet.</p>
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ background: "#1e3a5f", color: "#fff" }}>
              {["Vuln ID", "Title", "Severity", "Status"].map(h => (
                <th key={h} style={{ padding: "9px 12px", textAlign: "left", fontWeight: 500 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {mapped.map((f, i) => (
              <tr key={f.id} style={{ background: i % 2 === 0 ? "#fff" : "#f9fafb", borderBottom: "1px solid #e5e7eb" }}>
                <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "#1d4ed8" }}>{f.vuln_id}</td>
                <td style={{ padding: "8px 12px" }}>{f.title}</td>
                <td style={{ padding: "8px 12px" }}>{f.severity || "—"}</td>
                <td style={{ padding: "8px 12px" }}><StatusBadge status={f.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ background: color, borderRadius: 8, padding: "0.875rem 1rem" }}>
      <div style={{ fontSize: 11, color: "#6b7280", fontWeight: 500 }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 700 }}>{value}</div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, [string, string]> = {
    "Open": ["#fee2e2", "#b91c1c"], "Not a Finding": ["#dcfce7", "#15803d"],
    "Not Applicable": ["#f3f4f6", "#374151"], "Not Reviewed": ["#fef9c3", "#92400e"],
  };
  const [bg, color] = map[status] || ["#f3f4f6", "#374151"];
  return <span style={{ background: bg, color, padding: "2px 8px", borderRadius: 99, fontSize: 11, fontWeight: 500 }}>{status}</span>;
}

const backBtn: React.CSSProperties = { background: "none", border: "none", color: "#6b7280", cursor: "pointer", fontSize: 13, padding: 0, marginBottom: 8 };
const dlBtn: React.CSSProperties = { color: "#fff", textDecoration: "none", borderRadius: 6, padding: "8px 16px", fontSize: 14, fontWeight: 500 };
