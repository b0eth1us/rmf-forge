from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Enum
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
    stable_key = Column(String(512), nullable=False)  # deterministic hash for re-import matching
    source_tool = Column(String(50))   # fortify | zap | csv | xlsx
    severity = Column(String(50))
    title = Column(Text)
    description = Column(Text)
    plugin_id = Column(String(255))
    cwe_id = Column(String(50))
    cve_id = Column(String(50))
    cci_id = Column(String(50))
    vuln_id = Column(String(50))       # ASD STIG Vuln ID
    status = Column(Enum(FindingStatus), default=FindingStatus.not_reviewed)
    justification = Column(Text)       # persists across re-imports
    raw_data = Column(Text)            # JSON blob of original row
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    project = relationship("Project", back_populates="findings")
