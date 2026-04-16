from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://rmfforge:rmfforge@postgres:5432/rmfforge"
    SECRET_KEY: str = "dev-secret-change-in-production"
    PROJECT_DATA_DIR: str = "/app/data/projects"

    class Config:
        env_file = ".env"

settings = Settings()
