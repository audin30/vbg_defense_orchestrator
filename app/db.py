import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# SQLite by default (zero-setup dev); point at Postgres for the full stack:
#   DATABASE_URL=postgresql+psycopg2://orchestrator:orchestrator@localhost:5432/orchestrator
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./orchestrator.db")

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
