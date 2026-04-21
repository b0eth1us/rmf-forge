"""Add Fortify audit, ZAP, dep-check, POA&M, and host columns

Revision ID: 001
Revises:
Create Date: 2026-01-01
"""
from alembic import op
import sqlalchemy as sa

revision = '001'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Fortify audit.xml + FVDL fields
    op.add_column('findings', sa.Column('audit_comment', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('audit_action', sa.String(100), nullable=True))
    op.add_column('findings', sa.Column('file_path', sa.String(1024), nullable=True))
    op.add_column('findings', sa.Column('line_number', sa.Integer(), nullable=True))
    op.add_column('findings', sa.Column('code_snippet', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('taint_trace', sa.Text(), nullable=True))
    # Control mapping
    op.add_column('findings', sa.Column('nist_control', sa.String(100), nullable=True))
    # ZAP
    op.add_column('findings', sa.Column('affected_url', sa.Text(), nullable=True))
    # Dependency Check
    op.add_column('findings', sa.Column('dependency_name', sa.String(512), nullable=True))
    op.add_column('findings', sa.Column('dependency_version', sa.String(100), nullable=True))
    # POA&M
    op.add_column('findings', sa.Column('scheduled_completion_date', sa.Date(), nullable=True))
    op.add_column('findings', sa.Column('milestone_description', sa.Text(), nullable=True))
    # Project host fields
    op.add_column('projects', sa.Column('host_name', sa.String(255), nullable=True))
    op.add_column('projects', sa.Column('host_ip', sa.String(50), nullable=True))

def downgrade():
    for col in ['audit_comment','audit_action','file_path','line_number','code_snippet',
                'taint_trace','nist_control','affected_url','dependency_name',
                'dependency_version','scheduled_completion_date','milestone_description']:
        op.drop_column('findings', col)
    op.drop_column('projects', 'host_name')
    op.drop_column('projects', 'host_ip')
