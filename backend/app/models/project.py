from sqlalchemy import Column, String, DateTime, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base
import uuid
from datetime import datetime

class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    system_name = Column(String(255))
    description = Column(Text)
    host_name = Column(String(255))         # for .ckl HOST_NAME
    host_ip = Column(String(50))            # for .ckl HOST_IP
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    imports = relationship("ImportLog", back_populates="project", cascade="all, delete-orphan")
