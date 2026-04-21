import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { projectsApi, findingsApi, api } from "../utils/api";
import type { Project, Finding } from "../types";

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [editingProject, setEditingProject] = useState(false);
  const [hostForm, setHostForm] = useState({ host_name: "", host_ip: "" });
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const { data: project, isLoading } = useQuery<Project>({
    queryKey: ["project", id],
    queryFn: () => projectsApi.get(id!),
  });

  useEffect(() => {
    if (project) setHostForm({ host_name: project.host_name || "", host_ip: project.host_ip || "" });
  }, [project]);

  const { data: summary } = useQuery({
    queryKey: ["findings-summary", id],
    queryFn: () => findingsApi.summary(id!),
    enabled: !!id,
  });

  const { data: findings = [] } = useQuery<Finding[]>({
    queryKey: ["findings", id],
    queryFn: () => findingsApi.list(id!),
    enabled: !!id,
  });

  const updateProjectMut = useMutation({
    mutationFn: (data: any) => api.patch(`/projects/${id}`, data).then(r => r.data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["project", id] }); setEditingProject(false); },
  });

  const updateFindingMut = useMutation({
    mutationFn: ({ fid, data }: { fid: string; data: any }) =>
      findingsApi.update(fid, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings", id] }),
  });

  if (isLoading) return <div style={{ padding: "2rem", color: "#6b7280" }}>Loading…</div>;
  if (!project) return <div style={{ padding: "2rem", color: "#ef4444" }}>Project not found.</div>;

  const statusColors: Record<string, string> = {
    "Open": "#fee2e2", "Not a Finding": "#dcfce7",
    "Not Applicable": "#f3f4f6", "Not Reviewed": "#fef9c3",
  };

  return (
    <div style={{ padding: "2rem", maxWidth: 1100 }}>
      <button onClick={() => navigate("/")} style={backBtn}>← Projects</button>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ margin: "0.5rem 0 0.25rem", fontSize: 22, fontWeight: 600 }}>{project.name}</h1>
          {project.system_name && <p style={{ margin: 0, color: "#6b7280", fontSize: 14 }}>{project.system_name}</p>}
        </div>
        <button onClick={() => setEditingProject(!editingProject)} style={ghostBtn}>
          {editingProject ? "Cancel" : "⚙ Edit Project"}
        </button>
      </div>

      {editingProject && (
        <div style={{ ...card, marginBottom: "1.5rem", background: "#eff6ff", border: "1px solid #bfdbfe" }}>
          <h3 style={{ margin: "0 0 1rem", fontSize: 14, fontWeight: 600 }}>Host details (required for .ckl export)</h3>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <label style={labelStyle}>Host Name</label>
              <input value={hostForm.host_name} onChange={e => setHostForm(f => ({ ...f, host_name: e.target.value }))}
                placeholder="e.g. myapp-server" style={inputStyle} />
            </div>
            <div>
              <label style={labelStyle}>Host IP</label>
              <input value={hostForm.host_ip} onChange={e => setHostForm(f => ({ ...f, host_ip: e.target.value }))}
                placeholder="e.g. 10.0.0.1" style={inputStyle} />
            </div>
          </div>
          <button onClick={() => updateProjectMut.mutate(hostForm)} style={{ ...btnStyle, marginTop: 12 }}>
            Save
          </button>
        </div>
      )}

      {summary && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10, marginBottom: "1.5rem" }}>
          <StatCard label="Total" value={summary.total} color="#dbeafe" />
          {Object.entries(summary.by_status || {}).map(([k, v]) => (
            <StatCard key={k} label={k} value={v as number} color={statusColors[k] || "#f3f4f6"} />
          ))}
        </div>
      )}

      {/* Module cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginBottom: "2rem" }}>
        <ModuleCard title="Consolidate Scans" desc="Import .fpr, ZAP, dep-check, CSV, XLSX"
          action={() => navigate(`/projects/${id}/consolidate`)} icon="📥" />
        <ModuleCard title="STIG Checklist" desc="Export ASD STIG .ckl and XCCDF XML"
          action={() => navigate(`/projects/${id}/stig`)} icon="🛡️" />
        <ModuleCard title="ZAP → CCI Mapper" desc="Map OWASP ZAP alerts to CCIs for eMASS"
          action={() => navigate(`/projects/${id}/zap`)} icon="🔗" />
      </div>

      {/* Export buttons */}
      <div style={{ display: "flex", gap: 10, marginBottom: "1.5rem", flexWrap: "wrap" }}>
        <a href={`/api/export/consolidated/${id}`} style={{ ...dlBtn, background: "#059669" }}>
          ⬇ Excel Workbook
        </a>
        <a href={`/api/stig/export/${id}/ckl`} style={{ ...dlBtn, background: "#1d4ed8" }}>
          ⬇ STIG Viewer .ckl
        </a>
        <a href={`/api/stig/export/${id}/xccdf`} style={{ ...dlBtn, background: "#0369a1" }}>
          ⬇ XCCDF XML
        </a>
        <PackageButton projectId={id!} />
      </div>

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
        <h2 style={{ margin: 0, fontSize: 17, fontWeight: 600 }}>Findings</h2>
        <span style={{ fontSize: 13, color: "#6b7280" }}>{findings.length} total</span>
      </div>
      <FindingsTable
        findings={findings}
        expandedId={expandedFinding}
        onExpand={setExpandedFinding}
        onUpdate={(fid, data) => updateFindingMut.mutate({ fid, data })}
      />
    </div>
  );
}

function PackageButton({ projectId }: { projectId: string }) {
  const [loading, setLoading] = useState(false);
  const download = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/export/package/${projectId}`, { method: "POST" });
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "evidence_package.zip"; a.click();
      URL.revokeObjectURL(url);
    } finally { setLoading(false); }
  };
  return (
    <button onClick={download} disabled={loading}
      style={{ ...dlBtn, background: loading ? "#9ca3af" : "#7c3aed", border: "none", cursor: loading ? "wait" : "pointer" }}>
      {loading ? "Generating…" : "📦 Generate Evidence Package"}
    </button>
  );
}

function FindingsTable({ findings, expandedId, onExpand, onUpdate }: {
  findings: Finding[];
  expandedId: string | null;
  onExpand: (id: string | null) => void;
  onUpdate: (id: string, data: any) => void;
}) {
  const [editState, setEditState] = useState<Record<string, any>>({});

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
            {["Tool","Severity","Title","File / URL","CWE","CCI","STIG ID","Status","Justification"].map(h => (
              <th key={h} style={{ padding: "10px 10px", textAlign: "left", fontWeight: 500, whiteSpace: "nowrap" }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => {
            const isExpanded = expandedId === f.id;
            const edit = editState[f.id] || {};
            return (
              <>
                <tr key={f.id}
                  style={{ background: i % 2 === 0 ? "#fff" : "#f9fafb", borderBottom: "1px solid #e5e7eb", cursor: "pointer" }}
                  onClick={() => onExpand(isExpanded ? null : f.id)}>
                  <td style={{ padding: "8px 10px" }}><ToolBadge tool={f.source_tool} /></td>
                  <td style={{ padding: "8px 10px", background: sevColor[(f.severity||"").toLowerCase()] || "" }}>
                    {f.severity || "—"}
                  </td>
                  <td style={{ padding: "8px 10px", maxWidth: 250 }}>{f.title || "—"}</td>
                  <td style={{ padding: "8px 10px", maxWidth: 200, color: "#6b7280", fontSize: 12 }}>
                    {f.file_path || f.affected_url || "—"}
                    {f.line_number ? `:${f.line_number}` : ""}
                  </td>
                  <td style={{ padding: "8px 10px", color: "#6b7280" }}>{f.cwe_id || "—"}</td>
                  <td style={{ padding: "8px 10px", color: "#6b7280" }}>{f.cci_id || "—"}</td>
                  <td style={{ padding: "8px 10px", fontFamily: "monospace", fontSize: 11, color: "#1d4ed8" }}>{f.vuln_id || "—"}</td>
                  <td style={{ padding: "8px 10px" }}><StatusBadge status={f.status} /></td>
                  <td style={{ padding: "8px 10px", color: "#6b7280", maxWidth: 180, fontSize: 12 }}>
                    {f.justification || <span style={{ color: "#d1d5db" }}>—</span>}
                  </td>
                </tr>
                {isExpanded && (
                  <tr key={`${f.id}-expanded`} style={{ background: "#f0f9ff", borderBottom: "2px solid #bfdbfe" }}>
                    <td colSpan={9} style={{ padding: "1rem 1.5rem" }}>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                        <div>
                          {f.audit_comment && (
                            <div style={{ marginBottom: 8 }}>
                              <span style={detailLabel}>Developer Comment</span>
                              <p style={detailText}>{f.audit_comment}</p>
                            </div>
                          )}
                          {f.taint_trace && (
                            <div style={{ marginBottom: 8 }}>
                              <span style={detailLabel}>Taint Trace</span>
                              <p style={{ ...detailText, fontFamily: "monospace", fontSize: 11 }}>{f.taint_trace}</p>
                            </div>
                          )}
                          {f.code_snippet && (
                            <div style={{ marginBottom: 8 }}>
                              <span style={detailLabel}>Code Snippet</span>
                              <pre style={{ ...detailText, background: "#1e293b", color: "#e2e8f0", borderRadius: 6, padding: 8, fontSize: 11, overflow: "auto" }}>
                                {f.code_snippet}
                              </pre>
                            </div>
                          )}
                          {f.dependency_name && (
                            <div style={{ marginBottom: 8 }}>
                              <span style={detailLabel}>Dependency</span>
                              <p style={detailText}>{f.dependency_name} {f.dependency_version}</p>
                            </div>
                          )}
                        </div>
                        <div>
                          <div style={{ marginBottom: 10 }}>
                            <label style={detailLabel}>Status</label>
                            <select
                              value={edit.status ?? f.status}
                              onChange={e => setEditState(s => ({ ...s, [f.id]: { ...s[f.id], status: e.target.value } }))}
                              style={{ ...inputStyle, width: "100%" }}>
                              <option value="Open">Open</option>
                              <option value="Not a Finding">Not a Finding</option>
                              <option value="Not Applicable">Not Applicable</option>
                              <option value="Not Reviewed">Not Reviewed</option>
                            </select>
                          </div>
                          <div style={{ marginBottom: 10 }}>
                            <label style={detailLabel}>Justification</label>
                            <textarea
                              value={edit.justification ?? f.justification ?? ""}
                              onChange={e => setEditState(s => ({ ...s, [f.id]: { ...s[f.id], justification: e.target.value } }))}
                              style={{ ...inputStyle, width: "100%", minHeight: 80, resize: "vertical" }}
                              placeholder="Enter justification or comments…" />
                          </div>
                          {(edit.status === "Open" || (!edit.status && f.status === "Open")) && (
                            <>
                              <div style={{ marginBottom: 10 }}>
                                <label style={detailLabel}>Scheduled Completion Date</label>
                                <input type="date"
                                  value={edit.scheduled_completion_date ?? f.scheduled_completion_date ?? ""}
                                  onChange={e => setEditState(s => ({ ...s, [f.id]: { ...s[f.id], scheduled_completion_date: e.target.value } }))}
                                  style={{ ...inputStyle, width: "100%" }} />
                              </div>
                              <div style={{ marginBottom: 10 }}>
                                <label style={detailLabel}>Milestone Description</label>
                                <textarea
                                  value={edit.milestone_description ?? f.milestone_description ?? ""}
                                  onChange={e => setEditState(s => ({ ...s, [f.id]: { ...s[f.id], milestone_description: e.target.value } }))}
                                  style={{ ...inputStyle, width: "100%", minHeight: 60, resize: "vertical" }}
                                  placeholder="POA&M milestone…" />
                              </div>
                            </>
                          )}
                          <button
                            onClick={() => { onUpdate(f.id, edit); setEditState(s => { const n = { ...s }; delete n[f.id]; return n; }); }}
                            style={btnStyle}>Save changes</button>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            );
          })}
        </tbody>
      </table>
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
    <div onClick={action} style={{ background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10, padding: "1.25rem", cursor: "pointer" }}
      onMouseEnter={e => (e.currentTarget.style.borderColor = "#3b82f6")}
      onMouseLeave={e => (e.currentTarget.style.borderColor = "#e5e7eb")}>
      <div style={{ fontSize: 24, marginBottom: 8 }}>{icon}</div>
      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}>{title}</div>
      <div style={{ fontSize: 13, color: "#6b7280" }}>{desc}</div>
    </div>
  );
}

function ToolBadge({ tool }: { tool: string }) {
  const map: Record<string, [string, string]> = {
    fortify:    ["#ede9fe", "#5b21b6"],
    zap:        ["#e0f2fe", "#0369a1"],
    zap_xml:    ["#e0f2fe", "#0369a1"],
    zap_json:   ["#e0f2fe", "#0369a1"],
    dep_check:  ["#fef9c3", "#92400e"],
    csv:        ["#f3f4f6", "#374151"],
    xlsx:       ["#f0fdf4", "#15803d"],
  };
  const [bg, color] = map[tool] || ["#f3f4f6", "#374151"];
  return <span style={{ background: bg, color, padding: "2px 8px", borderRadius: 99, fontSize: 11, fontWeight: 500 }}>{tool}</span>;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, [string, string]> = {
    "Open": ["#fee2e2","#b91c1c"], "Not a Finding": ["#dcfce7","#15803d"],
    "Not Applicable": ["#f3f4f6","#374151"], "Not Reviewed": ["#fef9c3","#92400e"],
  };
  const [bg, color] = map[status] || ["#f3f4f6","#374151"];
  return <span style={{ background: bg, color, padding: "2px 8px", borderRadius: 99, fontSize: 11, fontWeight: 500, whiteSpace: "nowrap" }}>{status}</span>;
}

const backBtn: React.CSSProperties = { background: "none", border: "none", color: "#6b7280", cursor: "pointer", fontSize: 13, padding: 0, marginBottom: 8 };
const btnStyle: React.CSSProperties = { background: "#1d4ed8", color: "#fff", border: "none", borderRadius: 6, padding: "8px 16px", cursor: "pointer", fontSize: 14, fontWeight: 500 };
const ghostBtn: React.CSSProperties = { background: "transparent", color: "#374151", border: "1px solid #d1d5db", borderRadius: 6, padding: "7px 14px", cursor: "pointer", fontSize: 13 };
const dlBtn: React.CSSProperties = { color: "#fff", textDecoration: "none", borderRadius: 6, padding: "8px 14px", fontSize: 13, fontWeight: 500, display: "inline-block" };
const card: React.CSSProperties = { background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10, padding: "1.25rem" };
const inputStyle: React.CSSProperties = { border: "1px solid #d1d5db", borderRadius: 6, padding: "7px 10px", fontSize: 13, fontFamily: "inherit" };
const labelStyle: React.CSSProperties = { fontSize: 11, fontWeight: 600, color: "#6b7280", display: "block", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.05em" };
const detailLabel: React.CSSProperties = { fontSize: 11, fontWeight: 600, color: "#6b7280", display: "block", marginBottom: 4, textTransform: "uppercase" };
const detailText: React.CSSProperties = { margin: 0, fontSize: 13, color: "#374151", lineHeight: 1.6 };
