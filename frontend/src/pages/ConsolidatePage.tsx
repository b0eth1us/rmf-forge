import { useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { api } from "../utils/api";

type Suggestion = { original: string; confidence: number };
type SuggestionMap = Record<string, Suggestion[]>;

interface FileResult {
  filename: string;
  findings_added: number;
  findings_updated: number;
  findings_unchanged: number;
}

export default function ConsolidatePage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [phase, setPhase] = useState<"upload" | "mapping" | "importing" | "done">("upload");
  const [dragging, setDragging] = useState(false);
  const [files, setFiles] = useState<File[]>([]);
  const [currentFileIndex, setCurrentFileIndex] = useState(0);
  const [preview, setPreview] = useState<any>(null);
  const [approvedMap, setApprovedMap] = useState<Record<string, string>>({});
  const [results, setResults] = useState<FileResult[]>([]);
  const [error, setError] = useState("");

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setDragging(false);
    const dropped = Array.from(e.dataTransfer.files);
    if (dropped.length) setFiles(dropped);
  }, []);

  const NATIVE_TOOLS = ["fortify", "zap_xml", "zap_json", "dep_check_xml", "dep_check_json"];

  const handlePreview = async (fileIndex = 0) => {
    const file = files[fileIndex];
    if (!file) return;
    setError("");
    setCurrentFileIndex(fileIndex);
    const fd = new FormData();
    fd.append("file", file);
    try {
      const { data } = await api.post("/consolidate/preview", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setPreview(data);

      // Native formats (fpr, xml, json) have no columns to map — import immediately
      if (NATIVE_TOOLS.includes(data.tool)) {
        setApprovedMap({});
        await handleImportWithFile(file, fileIndex, {});
        return;
      }

      const init: Record<string, string> = {};
      for (const [canonical, suggestions] of Object.entries(data.suggestions as SuggestionMap)) {
        if (canonical === "__unmatched__") continue;
        const best = (suggestions as Suggestion[]).sort((a, b) => b.confidence - a.confidence)[0];
        if (best) init[canonical] = best.original;
      }
      setApprovedMap(init);
      setPhase("mapping");
    } catch (e: any) {
      setError(e.response?.data?.detail || `Failed to parse ${file.name}`);
    }
  };

  const handleImportWithFile = async (
    file: File,
    fileIndex: number,
    colMap: Record<string, string>,
  ) => {
    if (!id) return;
    setPhase("importing");
    const fd = new FormData();
    fd.append("file", file);
    fd.append("column_map", JSON.stringify(colMap));
    try {
      const { data } = await api.post(`/consolidate/import/${id}`, fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      const newResult: FileResult = {
        filename: file.name,
        findings_added: data.findings_added,
        findings_updated: data.findings_updated,
        findings_unchanged: data.findings_unchanged,
      };
      setResults(prev => {
        const updated = [...prev, newResult];
        return updated;
      });

      const nextIndex = fileIndex + 1;
      if (nextIndex < files.length) {
        setPreview(null);
        await handlePreview(nextIndex);
      } else {
        setPhase("done");
      }
    } catch (e: any) {
      setError(e.response?.data?.detail || "Import failed");
      setPhase("mapping");
    }
  };

  const handleImport = () =>
    handleImportWithFile(files[currentFileIndex], currentFileIndex, approvedMap);

  const totalAdded = results.reduce((s, r) => s + r.findings_added, 0);
  const totalUpdated = results.reduce((s, r) => s + r.findings_updated, 0);
  const totalUnchanged = results.reduce((s, r) => s + r.findings_unchanged, 0);

  return (
    <div style={{ padding: "2rem", maxWidth: 800 }}>
      <button onClick={() => navigate(`/projects/${id}`)} style={backBtn}>← Project</button>
      <h1 style={{ margin: "0.5rem 0 1.5rem", fontSize: 22, fontWeight: 600 }}>Consolidate Scans</h1>

      {error && <div style={errorBox}>{error}</div>}

      {phase === "upload" && (
        <div>
          <div
            onDrop={handleDrop}
            onDragOver={e => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            style={{
              border: `2px dashed ${dragging ? "#3b82f6" : "#d1d5db"}`,
              borderRadius: 10, padding: "3rem", textAlign: "center",
              background: dragging ? "#eff6ff" : "#f9fafb", transition: "all 0.15s",
            }}
          >
            <div style={{ fontSize: 36, marginBottom: 12 }}>📂</div>
            <p style={{ margin: "0 0 12px", fontWeight: 500 }}>
              {files.length > 0
                ? `${files.length} file${files.length > 1 ? "s" : ""} selected: ${files.map(f => f.name).join(", ")}`
                : "Drop scan files here"}
            </p>
            <p style={{ margin: "0 0 16px", fontSize: 13, color: "#6b7280" }}>
              Supported: .fpr (Fortify), .xml / .json (ZAP), .csv, .xlsx — select multiple files at once
            </p>
            <label style={btnStyle}>
              Browse files
              <input
                type="file"
                accept=".fpr,.csv,.xlsx,.xml,.json"
                multiple
                style={{ display: "none" }}
                onChange={e => setFiles(Array.from(e.target.files || []))}
              />
            </label>
          </div>
          {files.length > 0 && (
            <div style={{ marginTop: "1rem" }}>
              <div style={{ marginBottom: 10, display: "flex", flexDirection: "column", gap: 6 }}>
                {files.map((f, i) => (
                  <div key={i} style={{ fontSize: 13, color: "#374151", background: "#f3f4f6", borderRadius: 6, padding: "6px 12px", display: "flex", justifyContent: "space-between" }}>
                    <span>📄 {f.name}</span>
                    <span style={{ color: "#9ca3af" }}>{(f.size / 1024).toFixed(1)} KB</span>
                  </div>
                ))}
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                <button onClick={() => handlePreview(0)} style={btnStyle}>Analyze Columns →</button>
                <button onClick={() => setFiles([])} style={ghostBtn}>Clear</button>
              </div>
            </div>
          )}
        </div>
      )}

      {phase === "mapping" && preview && (
        <div>
          <div style={infoBox}>
            <strong>{preview.filename}</strong> — {preview.row_count} rows detected as <code>{preview.tool}</code>
            {files.length > 1 && (
              <span style={{ marginLeft: 12, fontSize: 12, color: "#6b7280" }}>
                File {currentFileIndex + 1} of {files.length}
              </span>
            )}
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 600, margin: "1.5rem 0 0.75rem" }}>Review column mapping</h2>
          <p style={{ fontSize: 13, color: "#6b7280", margin: "0 0 1rem" }}>
            Adjust which source column maps to each canonical field. Unmatched columns are appended as-is.
          </p>

          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, marginBottom: "1rem" }}>
            <thead>
              <tr style={{ background: "#1e3a5f", color: "#fff" }}>
                {["Canonical field", "Mapped to", "Confidence"].map(h => (
                  <th key={h} style={{ padding: "9px 12px", textAlign: "left", fontWeight: 500 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Object.entries(preview.suggestions as SuggestionMap)
                .filter(([k]) => k !== "__unmatched__")
                .map(([canonical, suggestions], i) => (
                  <tr key={canonical} style={{ background: i % 2 === 0 ? "#fff" : "#f9fafb", borderBottom: "1px solid #e5e7eb" }}>
                    <td style={{ padding: "8px 12px", fontWeight: 500 }}>{canonical}</td>
                    <td style={{ padding: "8px 12px" }}>
                      <select
                        value={approvedMap[canonical] || ""}
                        onChange={e => setApprovedMap(m => ({ ...m, [canonical]: e.target.value }))}
                        style={{ border: "1px solid #d1d5db", borderRadius: 5, padding: "4px 8px", fontSize: 13 }}
                      >
                        <option value="">— skip —</option>
                        {preview.columns.map((c: string) => <option key={c} value={c}>{c}</option>)}
                      </select>
                    </td>
                    <td style={{ padding: "8px 12px" }}>
                      {suggestions[0] ? <ConfidenceBadge value={suggestions[0].confidence} /> : "—"}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>

          {(preview.suggestions.__unmatched__ || []).length > 0 && (
            <div style={{ background: "#fffbeb", border: "1px solid #fcd34d", borderRadius: 8, padding: "0.875rem 1rem", marginBottom: "1rem" }}>
              <strong style={{ fontSize: 13 }}>Unmatched columns</strong> — will be appended as extra columns:
              <span style={{ marginLeft: 8, fontSize: 13, color: "#6b7280" }}>
                {preview.suggestions.__unmatched__.map((u: Suggestion) => u.original).join(", ")}
              </span>
            </div>
          )}

          <div style={{ display: "flex", gap: 10 }}>
            <button onClick={handleImport} style={btnStyle}>
              {currentFileIndex + 1 < files.length ? `Import & Next File →` : "Import Findings →"}
            </button>
            <button onClick={() => { setPhase("upload"); setPreview(null); setResults([]); }} style={ghostBtn}>Back</button>
          </div>
        </div>
      )}

      {phase === "importing" && (
        <div style={{ textAlign: "center", padding: "3rem", color: "#6b7280" }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>⏳</div>
          Importing {files[currentFileIndex]?.name}… ({currentFileIndex + 1} of {files.length})
        </div>
      )}

      {phase === "done" && (
        <div style={{ ...infoBox, background: "#f0fdf4", borderColor: "#86efac" }}>
          <div style={{ fontSize: 18, marginBottom: 12 }}>✅ Import complete — {results.length} file{results.length > 1 ? "s" : ""} processed</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: "1rem" }}>
            <ResultStat label="New findings" value={totalAdded} color="#dcfce7" />
            <ResultStat label="Updated" value={totalUpdated} color="#fef9c3" />
            <ResultStat label="Unchanged" value={totalUnchanged} color="#f3f4f6" />
          </div>
          {results.length > 1 && (
            <div style={{ marginBottom: "1rem" }}>
              {results.map((r, i) => (
                <div key={i} style={{ fontSize: 13, color: "#374151", padding: "4px 0", borderBottom: "1px solid #d1fae5" }}>
                  <strong>{r.filename}</strong> — {r.findings_added} new, {r.findings_updated} updated, {r.findings_unchanged} unchanged
                </div>
              ))}
            </div>
          )}
          <button onClick={() => navigate(`/projects/${id}`)} style={{ ...btnStyle, marginTop: "0.5rem" }}>
            View Findings →
          </button>
        </div>
      )}
    </div>
  );
}

function ConfidenceBadge({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct >= 80 ? "#15803d" : pct >= 50 ? "#92400e" : "#b91c1c";
  const bg = pct >= 80 ? "#dcfce7" : pct >= 50 ? "#fef9c3" : "#fee2e2";
  return <span style={{ background: bg, color, borderRadius: 99, padding: "2px 8px", fontSize: 11, fontWeight: 600 }}>{pct}%</span>;
}

function ResultStat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ background: color, borderRadius: 8, padding: "0.75rem 1rem", textAlign: "center" }}>
      <div style={{ fontSize: 22, fontWeight: 700 }}>{value}</div>
      <div style={{ fontSize: 12, color: "#6b7280" }}>{label}</div>
    </div>
  );
}

const backBtn: React.CSSProperties = { background: "none", border: "none", color: "#6b7280", cursor: "pointer", fontSize: 13, padding: 0, marginBottom: 8 };
const btnStyle: React.CSSProperties = { background: "#1d4ed8", color: "#fff", border: "none", borderRadius: 6, padding: "8px 16px", cursor: "pointer", fontSize: 14, fontWeight: 500 };
const ghostBtn: React.CSSProperties = { background: "transparent", color: "#374151", border: "1px solid #d1d5db", borderRadius: 6, padding: "7px 14px", cursor: "pointer", fontSize: 13 };
const errorBox: React.CSSProperties = { background: "#fef2f2", border: "1px solid #fca5a5", borderRadius: 8, padding: "0.875rem 1rem", color: "#b91c1c", marginBottom: "1rem", fontSize: 14 };
const infoBox: React.CSSProperties = { background: "#eff6ff", border: "1px solid #bfdbfe", borderRadius: 8, padding: "0.875rem 1rem", marginBottom: "1rem", fontSize: 14 };
