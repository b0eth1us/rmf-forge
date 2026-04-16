import { Link, useLocation, useParams } from "react-router-dom";
import type { ReactNode } from "react";

export default function Layout({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();

  return (
    <div style={{ display: "flex", minHeight: "100vh", fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" }}>
      <nav style={{
        width: 220, background: "#0f172a", color: "#fff",
        padding: "1.25rem 0.875rem", display: "flex",
        flexDirection: "column", gap: 4, flexShrink: 0,
      }}>
        <Link to="/" style={{ textDecoration: "none" }}>
          <div style={{ fontWeight: 700, fontSize: 17, marginBottom: "1.25rem", color: "#60a5fa", letterSpacing: "-0.3px" }}>
            🔒 RMF Forge
          </div>
        </Link>
        <NavItem to="/" label="Projects" active={pathname === "/"} />
        <div style={{ marginTop: "auto", padding: "0.75rem 0.5rem", borderTop: "1px solid #1e293b" }}>
          <div style={{ fontSize: 10, color: "#475569", lineHeight: 1.6 }}>
            Air-gapped · CUI-safe<br />v0.1.0 · Zero network egress
          </div>
        </div>
      </nav>
      <main style={{ flex: 1, overflow: "auto", background: "#f8fafc" }}>{children}</main>
    </div>
  );
}

function NavItem({ to, label, active }: { to: string; label: string; active: boolean }) {
  return (
    <Link to={to} style={{
      color: active ? "#60a5fa" : "#94a3b8",
      textDecoration: "none", padding: "6px 10px",
      borderRadius: 6, fontSize: 14,
      background: active ? "rgba(96,165,250,0.1)" : "transparent",
      display: "block",
    }}>{label}</Link>
  );
}
