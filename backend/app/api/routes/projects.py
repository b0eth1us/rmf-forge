from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.project import Project
from pydantic import BaseModel
from typing import Optional
import uuid

router = APIRouter()

class ProjectCreate(BaseModel):
    name: str
    system_name: Optional[str] = None
    description: Optional[str] = None

class ProjectResponse(BaseModel):
    id: uuid.UUID
    name: str
    system_name: Optional[str]
    description: Optional[str]
    class Config:
        from_attributes = True

@router.get("/", response_model=list[ProjectResponse])
def list_projects(db: Session = Depends(get_db)):
    return db.query(Project).order_by(Project.updated_at.desc()).all()

@router.post("/", response_model=ProjectResponse, status_code=201)
def create_project(data: ProjectCreate, db: Session = Depends(get_db)):
    project = Project(**data.model_dump())
    db.add(project)
    db.commit()
    db.refresh(project)
    return project

@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: uuid.UUID, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@router.delete("/{project_id}", status_code=204)
def delete_project(project_id: uuid.UUID, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    db.delete(project)
    db.commit()
