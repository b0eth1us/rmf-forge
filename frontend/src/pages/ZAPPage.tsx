import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { api } from "../utils/api";

export default function ZAPPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleMap = async () => {
    if (!file || !id) return;
    setLoading(true); setError("");
    const fd = new FormData();
    fd.append("file", file);
    try {
      const { data } = await api.post(`/zap/map/${id}`, fd, { headers: { "Content-Type": "multipart/form-data" } });
      setResult(data);
    } catch (e: any) {
      setError(e.response?.data?.detail || "Mapping failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "2rem", maxWidth: 900 }}>
      <button onClick={() => navigate(`/projects/${id}`)} style={backBtn}>← Project</button>
      <h1 style={{ margin: "0.5rem 0 0.25rem", fontSize: 22, fontWeight: 600 }}>ZAP → CCI Mapper</h1>
      <p style={{ margin: "0 0 1.5rem", color: "#6b7280", fontSize: 14 }}>
        Map OWASP ZAP CWE alerts to DoD CCIs and export the eMASS bulk upload template
      </p>

      {error && <div style={errorBox}>{error}</div>}

      {!result && (
        <div style={{ background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10, padding: "1.5rem" }}>
          <div style={{ marginBottom: "1rem" }}>
            <label style={{ fontSize: 14, fontWeight: 500, display: "block", marginBottom: 6 }}>
              ZAP report file (.xml or .json)
            </label>
            <input type="file" accept=".xml,.json"
              onChange={e => setFile(e.target.files?.[0] || null)}
              style={{ fontSize: 14 }} />
          </div>
          <button onClick={handleMap} disabled={!file || loading} style={btnStyle}>
            {loading ? "Mapping…" : "Map CWEs to CCIs →"}
          </button>
        </div>
      )}

      {result && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: "1.5rem" }}>
            <StatCard label="Total alerts" value={result.total} color="#dbeafe" />
            <StatCard label="Mapped to CCI" value={result.mapped_count} color="#dcfce7" />
            <StatCard label="Unmapped" value={result.unmapped_count} color="#fee2e2" />
          </div>

          <a href={`/api/export/emass-zap/${id}`} style={{ ...dlBtn, display: "inline-block", marginBottom: "1.5rem" }}>
            ⬇ Download eMASS Bulk Upload Excel
          </a>

          <h2 style={{ fontSize: 16, fontWeight: 600, margin: "0 0 0.75rem" }}>Mapped findings</h2>
          {result.mapped.length === 0 ? (
            <p style={{ color: "#6b7280", fontSize: 14 }}>No mappings found.</p>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, marginBottom: "1.5rem" }}>
              <thead>
                <tr style={{ background: "#1e3a5f", color: "#fff" }}>
                  {["Alert", "CWE", "CCIs", "Severity"].map(h => (
                    <th key={h} style={{ padding: "9px 12px", textAlign: "left", fontWeight: 500 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {result.mapped.map((m: any, i: number) => (
                  <tr key={i} style={{ background: i % 2 === 0 ? "#fff" : "#f9fafb", borderBottom: "1px solid #e5e7eb" }}>
                    <td style={{ padding: "8px 12px" }}>{m.title || "—"}</td>
                    <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "#1d4ed8" }}>CWE-{m.cwe_id}</td>
                    <td style={{ padding: "8px 12px" }}>
                      {m.ccis.map((c: any) => (
                        <span key={c.cci_id} style={{ background: "#ede9fe", color: "#5b21b6", borderRadius: 99, padding: "2px 7px", fontSize: 11, marginRight: 4, fontWeight: 500 }}>
                          {c.cci_id}
                        </span>
                      ))}
                    </td>
                    <td style={{ padding: "8px 12px", color: "#6b7280" }}>{m.severity || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {result.unmapped.length > 0 && (
            <>
              <h2 style={{ fontSize: 16, fontWeight: 600, margin: "0 0 0.75rem", color: "#b91c1c" }}>
                ⚠️ Unmapped CWEs ({result.unmapped.length})
              </h2>
              <div style={{ background: "#fef2f2", border: "1px solid #fca5a5", borderRadius: 8, padding: "1rem" }}>
                <p style={{ margin: "0 0 8px", fontSize: 13, color: "#6b7280" }}>
                  These CWEs have no CCI mapping. They appear on the "Unmapped CWEs" sheet in the eMASS export for manual disposition.
                </p>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                  <thead>
                    <tr style={{ background: "#b91c1c", color: "#fff" }}>
                      {["Alert", "CWE ID"].map(h => (
                        <th key={h} style={{ padding: "7px 10px", textAlign: "left", fontWeight: 500 }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {result.unmapped.map((u: any, i: number) => (
                      <tr key={i} style={{ borderBottom: "1px solid #fecaca" }}>
                        <td style={{ padding: "6px 10px" }}>{u.title || "—"}</td>
                        <td style={{ padding: "6px 10px", fontFamily: "monospace" }}>
                          {u.cwe_id !== "unknown" ? `CWE-${u.cwe_id}` : "No CWE"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          <button onClick={() => { setResult(null); setFile(null); }} style={{ ...ghostBtn, marginTop: "1rem" }}>
            Map another file
          </button>
        </div>
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

const backBtn: React.CSSProperties = { background: "none", border: "none", color: "#6b7280", cursor: "pointer", fontSize: 13, padding: 0, marginBottom: 8 };
const btnStyle: React.CSSProperties = { background: "#1d4ed8", color: "#fff", border: "none", borderRadius: 6, padding: "8px 16px", cursor: "pointer", fontSize: 14, fontWeight: 500 };
const ghostBtn: React.CSSProperties = { background: "transparent", color: "#374151", border: "1px solid #d1d5db", borderRadius: 6, padding: "7px 14px", cursor: "pointer", fontSize: 13 };
const dlBtn: React.CSSProperties = { background: "#059669", color: "#fff", textDecoration: "none", borderRadius: 6, padding: "8px 16px", fontSize: 14, fontWeight: 500 };
const errorBox: React.CSSProperties = { background: "#fef2f2", border: "1px solid #fca5a5", borderRadius: 8, padding: "0.875rem 1rem", color: "#b91c1c", marginBottom: "1rem", fontSize: 14 };
