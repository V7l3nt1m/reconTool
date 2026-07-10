import json
from datetime import datetime, timezone

from sqlalchemy import create_engine, Column, String, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base

DB_PATH = "sqlite:///./recon.db"
engine = create_engine(DB_PATH, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class Job(Base):
    __tablename__ = "jobs"

    id = Column(String, primary_key=True)
    target_url = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending | running | done | error
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime, nullable=True)
    report_json = Column(Text, nullable=True)  # relatório final serializado
    error_message = Column(Text, nullable=True)

    def report(self):
        return json.loads(self.report_json) if self.report_json else None


def init_db():
    Base.metadata.create_all(bind=engine)


def get_session():
    return SessionLocal()
