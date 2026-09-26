"""
Configuração da conexão com o banco de dados (SQLite + SQLAlchemy).
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vuln_dashboard.db")

# check_same_thread=False é necessário apenas para SQLite, pois o FastAPI
# pode acessar o banco a partir de threads diferentes.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency do FastAPI: entrega uma sessão de banco e garante o fechamento."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
