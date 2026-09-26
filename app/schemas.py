"""
Schemas Pydantic usados para validar requisições e formatar respostas.
"""
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Ativo
# ---------------------------------------------------------------------------

class AtivoBase(BaseModel):
    nome: str = Field(..., min_length=1, max_length=120, examples=["nginx"])
    versao: str = Field(..., min_length=1, max_length=60, examples=["1.18"])
    categoria: str = Field(..., min_length=1, max_length=80, examples=["servidor web"])


class AtivoCriar(AtivoBase):
    """Payload aceito em POST /ativos"""
    pass


class AtivoAtualizar(BaseModel):
    """Payload aceito em PUT /ativos/{id}. Todos os campos são opcionais."""
    nome: Optional[str] = Field(None, min_length=1, max_length=120)
    versao: Optional[str] = Field(None, min_length=1, max_length=60)
    categoria: Optional[str] = Field(None, min_length=1, max_length=80)


class AtivoResposta(AtivoBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    data_cadastro: datetime


class AtivoListaPaginada(BaseModel):
    total: int
    page: int
    page_size: int
    itens: list[AtivoResposta]


# ---------------------------------------------------------------------------
# Vulnerabilidades (NVD)
# ---------------------------------------------------------------------------

Severidade = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "DESCONHECIDA"]


class VulnerabilidadeResposta(BaseModel):
    cve_id: str
    descricao: str
    score_cvss: Optional[float] = None
    severidade: Severidade = "DESCONHECIDA"
    data_publicacao: Optional[datetime] = None


class VulnerabilidadesResposta(BaseModel):
    ativo_id: int
    termo_busca: str
    total_encontrado: int
    vulnerabilidades: list[VulnerabilidadeResposta]
    origem_cache: bool = False


class ResumoSeveridade(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    DESCONHECIDA: int = 0


class ResumoResposta(BaseModel):
    ativo_id: int
    ativo_nome: str
    ativo_versao: str
    total_cves: int
    por_severidade: ResumoSeveridade
