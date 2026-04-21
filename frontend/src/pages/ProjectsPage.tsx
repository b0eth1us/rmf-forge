import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { projectsApi } from "../utils/api";
import type { Project } from "../types";

export default function ProjectsPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: "", system_name: "", description: "", host_name: "", host_ip: "" });

  const { data: projects = [], isLoading } = useQuery<Project[]>({
    queryKey: ["projects"],
    queryFn: projectsApi.list,
  });

  const createMut = useMutation({
    mutationFn: projectsApi.create,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects"] });
      setShowForm(false);
      setForm({ name: "", system_name: "", description: "", host_name: "", host_ip: "" });
    },
  });

  const deleteMut = useMutation({
    mutationFn: projectsApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
  });

  return (
    <div style={{ padding: "2rem", maxWidth: 900 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 24, fontWeight: 600 }}>Projects</h1>
          <p style={{ margin: "4px 0 0", color: "#6b7280", fontSize: 14 }}>Each project is a system or package under review</p>
        </div>
        <button onClick={() => setShowForm(true)} style={btnStyle}>+ New Project</button>
      </div>

      {showForm && (
        <div style={cardStyle}>
          <h3 style={{ margin: "0 0 1rem", fontSize: 16 }}>New project</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <input placeholder="Project name *" value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))} style={inputStyle} />
            <input placeholder="System name (e.g. MyApp v2.1)" value={form.system_name}
              onChange={e => setForm(f => ({ ...f, system_name: e.target.value }))} style={inputStyle} />
            <textarea placeholder="Description" value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              style={{ ...inputStyle, minHeight: 60, resize: "vertical" }} />
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <input placeholder="Host name (for .ckl)" value={form.host_name}
                onChange={e => setForm(f => ({ ...f, host_name: e.target.value }))} style={inputStyle} />
              <input placeholder="Host IP (for .ckl)" value={form.host_ip}
                onChange={e => setForm(f => ({ ...f, host_ip: e.target.value }))} style={inputStyle} />
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={() => createMut.mutate(form)} disabled={!form.name} style={btnStyle}>
                {createMut.isPending ? "Creating…" : "Create Project"}
              </button>
              <button onClick={() => setShowForm(false)} style={ghostBtnStyle}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {isLoading ? (
        <p style={{ color: "#6b7280" }}>Loading…</p>
      ) : projects.length === 0 ? (
        <div style={{ ...cardStyle, textAlign: "center", padding: "3rem", color: "#6b7280" }}>
          No projects yet. Create one to get started.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {projects.map(p => (
            <div key={p.id} style={{ ...cardStyle, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer" }}
              onClick={() => navigate(`/projects/${p.id}`)}>
              <div>
                <div style={{ fontWeight: 600, fontSize: 15 }}>{p.name}</div>
                {p.system_name && <div style={{ fontSize: 13, color: "#6b7280", marginTop: 2 }}>{p.system_name}</div>}
                {(p.host_name || p.host_ip) && (
                  <div style={{ fontSize: 12, color: "#9ca3af", marginTop: 2 }}>
                    {p.host_name}{p.host_ip ? ` · ${p.host_ip}` : ""}
                  </div>
                )}
              </div>
              <div style={{ display: "flex", gap: 8 }} onClick={e => e.stopPropagation()}>
                <button onClick={() => navigate(`/projects/${p.id}`)} style={ghostBtnStyle}>Open →</button>
                <button onClick={() => { if (confirm("Delete this project and all its findings?")) deleteMut.mutate(p.id); }}
                  style={{ ...ghostBtnStyle, color: "#ef4444", borderColor: "#fca5a5" }}>Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const cardStyle: React.CSSProperties = { background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10, padding: "1.25rem", marginBottom: 8 };
const btnStyle: React.CSSProperties = { background: "#1d4ed8", color: "#fff", border: "none", borderRadius: 6, padding: "8px 16px", cursor: "pointer", fontSize: 14, fontWeight: 500 };
const ghostBtnStyle: React.CSSProperties = { background: "transparent", color: "#374151", border: "1px solid #d1d5db", borderRadius: 6, padding: "7px 14px", cursor: "pointer", fontSize: 13 };
const inputStyle: React.CSSProperties = { border: "1px solid #d1d5db", borderRadius: 6, padding: "8px 12px", fontSize: 14, width: "100%", fontFamily: "inherit" };
