from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Enum, Integer, Date
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base
import uuid
from datetime import datetime
import enum

class FindingStatus(str, enum.Enum):
    open = "Open"
    not_a_finding = "Not a Finding"
    not_applicable = "Not Applicable"
    not_reviewed = "Not Reviewed"

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    stable_key = Column(String(512), nullable=False)
    source_tool = Column(String(50))        # fortify | zap | dep_check | csv | xlsx

    # Core finding fields
    severity = Column(String(50))
    title = Column(Text)
    description = Column(Text)
    plugin_id = Column(String(255))

    # Vulnerability identifiers
    cwe_id = Column(String(50))
    cve_id = Column(String(50))
    cci_id = Column(String(50))
    nist_control = Column(String(100))
    vuln_id = Column(String(50))            # ASD STIG Vuln ID

    # Status and justification
    status = Column(Enum(FindingStatus), default=FindingStatus.not_reviewed)
    justification = Column(Text)            # persists across re-imports

    # Fortify-specific — extracted from audit.xml + FVDL
    audit_comment = Column(Text)            # developer comment from audit.xml
    audit_action = Column(String(100))      # Not an Issue | Suppressed | etc.
    file_path = Column(String(1024))        # offending file
    line_number = Column(Integer)           # offending line
    code_snippet = Column(Text)             # source code at that line
    taint_trace = Column(Text)              # full call path string

    # ZAP-specific
    affected_url = Column(Text)

    # Dependency Check-specific
    dependency_name = Column(String(512))
    dependency_version = Column(String(100))

    # POA&M fields (Module 4)
    scheduled_completion_date = Column(Date)
    milestone_description = Column(Text)

    # Metadata
    raw_data = Column(Text)                 # original row JSON
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    project = relationship("Project", back_populates="findings")
