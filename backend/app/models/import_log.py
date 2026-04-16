from sqlalchemy import Column, String, DateTime, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base
import uuid
from datetime import datetime

class ImportLog(Base):
    __tablename__ = "import_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    filename = Column(String(512))
    file_hash = Column(String(64))     # SHA-256
    source_tool = Column(String(50))
    findings_added = Column(Integer, default=0)
    findings_updated = Column(Integer, default=0)
    findings_unchanged = Column(Integer, default=0)
    imported_at = Column(DateTime, default=datetime.utcnow)

    project = relationship("Project", back_populates="imports")
