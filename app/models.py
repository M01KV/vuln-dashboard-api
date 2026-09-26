"""
Modelos ORM (SQLAlchemy) do domínio da aplicação.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime

from app.database import Base


class Ativo(Base):
    """
    Representa um software/versão cadastrado na infraestrutura do usuário.

    Exemplo: nome="nginx", versao="1.18", categoria="servidor web"
    """

    __tablename__ = "ativos"

    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String(120), nullable=False, index=True)
    versao = Column(String(60), nullable=False)
    categoria = Column(String(80), nullable=False, index=True)
    data_cadastro = Column(DateTime, default=lambda: datetime.now(timezone.utc))
