export interface Project {
  id: string;
  name: string;
  system_name?: string;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  project_id: string;
  stable_key: string;
  source_tool: "fortify" | "zap" | "csv" | "xlsx";
  severity?: string;
  title?: string;
  description?: string;
  plugin_id?: string;
  cwe_id?: string;
  cve_id?: string;
  cci_id?: string;
  vuln_id?: string;
  status: "Open" | "Not a Finding" | "Not Applicable" | "Not Reviewed";
  justification?: string;
  first_seen: string;
  last_seen: string;
}

export type FindingStatus = Finding["status"];
