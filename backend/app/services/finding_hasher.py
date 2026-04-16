"""
Generates a stable key for a finding so justification comments
survive re-imports. Key is based on tool + plugin_id + title hash.
"""
import hashlib

def stable_key(source_tool: str, plugin_id: str | None, title: str | None) -> str:
    raw = f"{source_tool}::{plugin_id or ''}::{(title or '').lower().strip()}"
    return hashlib.sha256(raw.encode()).hexdigest()
