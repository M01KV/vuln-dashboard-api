"""
Painel de Vulnerabilidades por Software — API Back-End.

Arquitetura: Interface (Front-End) + API (Back-End) + API Externa (NVD).
"""
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.routers import ativos

# Cria as tabelas no SQLite caso ainda não existam.
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Painel de Vulnerabilidades por Software — API",
    description=(
        "API para cadastro de ativos (softwares/versões) e consulta de "
        "vulnerabilidades conhecidas (CVEs) via NVD API."
    ),
    version="1.0.0",
)

# CORS: em desenvolvimento aceitamos qualquer origem; em produção,
# defina CORS_ORIGINS separado por vírgulas (ex.: "https://meufront.com").
origens_configuradas = os.getenv("CORS_ORIGINS", "*")
origins = (
    ["*"] if origens_configuradas.strip() == "*" else origens_configuradas.split(",")
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ativos.router)


@app.get("/", tags=["Status"], summary="Health check")
def raiz():
    return {
        "status": "ok",
        "servico": "vuln-dashboard-api",
        "documentacao": "/docs",
    }
