export interface Project {
  id: string;
  name: string;
  system_name?: string;
  description?: string;
  host_name?: string;
  host_ip?: string;
  created_at?: string;
  updated_at?: string;
}

export interface Finding {
  id: string;
  project_id: string;
  source_tool: string;
  severity?: string;
  title?: string;
  description?: string;
  plugin_id?: string;
  cwe_id?: string;
  cve_id?: string;
  cci_id?: string;
  nist_control?: string;
  vuln_id?: string;
  status: "Open" | "Not a Finding" | "Not Applicable" | "Not Reviewed";
  justification?: string;
  audit_comment?: string;
  audit_action?: string;
  file_path?: string;
  line_number?: number;
  code_snippet?: string;
  taint_trace?: string;
  affected_url?: string;
  dependency_name?: string;
  dependency_version?: string;
  scheduled_completion_date?: string;
  milestone_description?: string;
  first_seen?: string;
  last_seen?: string;
}

export type FindingStatus = Finding["status"];
