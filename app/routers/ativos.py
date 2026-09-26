"""
Rotas relacionadas ao recurso Ativo: CRUD, consulta de vulnerabilidades
(via NVD) e resumo estatístico por severidade.
"""
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.auth import exigir_api_key
from app.database import get_db
from app.services import nvd_service

router = APIRouter(prefix="/ativos", tags=["Ativos"])


def _buscar_ativo_ou_404(ativo_id: int, db: Session) -> models.Ativo:
    ativo = db.query(models.Ativo).filter(models.Ativo.id == ativo_id).first()
    if ativo is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Ativo com id={ativo_id} não encontrado.",
        )
    return ativo


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

@router.post(
    "",
    response_model=schemas.AtivoResposta,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastra um novo ativo (software/versão)",
    dependencies=[Depends(exigir_api_key)],
)
def criar_ativo(payload: schemas.AtivoCriar, db: Session = Depends(get_db)):
    novo_ativo = models.Ativo(**payload.model_dump())
    db.add(novo_ativo)
    db.commit()
    db.refresh(novo_ativo)
    return novo_ativo


@router.get(
    "",
    response_model=schemas.AtivoListaPaginada,
    summary="Lista ativos cadastrados, com filtro, paginação e ordenação",
)
def listar_ativos(
    categoria: Optional[str] = Query(None, description="Filtra por categoria exata"),
    page: int = Query(1, ge=1, description="Número da página (inicia em 1)"),
    page_size: int = Query(10, ge=1, le=100, description="Itens por página"),
    ordenar_por: Literal["nome", "data"] = Query(
        "data", description="Campo de ordenação: 'nome' ou 'data'"
    ),
    db: Session = Depends(get_db),
):
    consulta = db.query(models.Ativo)

    if categoria:
        consulta = consulta.filter(models.Ativo.categoria.ilike(categoria))

    if ordenar_por == "nome":
        consulta = consulta.order_by(models.Ativo.nome.asc())
    else:
        consulta = consulta.order_by(models.Ativo.data_cadastro.desc())

    total = consulta.count()
    itens = consulta.offset((page - 1) * page_size).limit(page_size).all()

    return schemas.AtivoListaPaginada(
        total=total, page=page, page_size=page_size, itens=itens
    )


@router.put(
    "/{ativo_id}",
    response_model=schemas.AtivoResposta,
    summary="Atualiza um ativo existente",
    dependencies=[Depends(exigir_api_key)],
)
def atualizar_ativo(
    ativo_id: int, payload: schemas.AtivoAtualizar, db: Session = Depends(get_db)
):
    ativo = _buscar_ativo_ou_404(ativo_id, db)

    dados = payload.model_dump(exclude_unset=True)
    for campo, valor in dados.items():
        setattr(ativo, campo, valor)

    db.commit()
    db.refresh(ativo)
    return ativo


@router.delete(
    "/{ativo_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove um ativo",
    dependencies=[Depends(exigir_api_key)],
)
def remover_ativo(ativo_id: int, db: Session = Depends(get_db)):
    ativo = _buscar_ativo_ou_404(ativo_id, db)
    db.delete(ativo)
    db.commit()
    return None


# ---------------------------------------------------------------------------
# Integração com a NVD
# ---------------------------------------------------------------------------

@router.get(
    "/{ativo_id}/vulnerabilidades",
    response_model=schemas.VulnerabilidadesResposta,
    summary="Consulta CVEs relacionados ao ativo na NVD API",
)
async def consultar_vulnerabilidades(ativo_id: int, db: Session = Depends(get_db)):
    ativo = _buscar_ativo_ou_404(ativo_id, db)
    termo_busca = f"{ativo.nome} {ativo.versao}"

    try:
        vulnerabilidades, veio_do_cache = await nvd_service.buscar_cves(termo_busca)
    except nvd_service.NvdTimeoutError as exc:
        raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail=str(exc))
    except nvd_service.NvdRateLimitError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc))
    except nvd_service.NvdIndisponivelError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    return schemas.VulnerabilidadesResposta(
        ativo_id=ativo.id,
        termo_busca=termo_busca,
        total_encontrado=len(vulnerabilidades),
        vulnerabilidades=vulnerabilidades,
        origem_cache=veio_do_cache,
    )


@router.get(
    "/{ativo_id}/resumo",
    response_model=schemas.ResumoResposta,
    summary="Contagem de CVEs do ativo agrupados por severidade",
)
async def resumo_vulnerabilidades(ativo_id: int, db: Session = Depends(get_db)):
    ativo = _buscar_ativo_ou_404(ativo_id, db)
    termo_busca = f"{ativo.nome} {ativo.versao}"

    try:
        vulnerabilidades, _ = await nvd_service.buscar_cves(termo_busca)
    except nvd_service.NvdTimeoutError as exc:
        raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail=str(exc))
    except nvd_service.NvdRateLimitError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc))
    except nvd_service.NvdIndisponivelError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    contagem = schemas.ResumoSeveridade()
    for vulnerabilidade in vulnerabilidades:
        severidade = vulnerabilidade.get("severidade") or "DESCONHECIDA"
        if hasattr(contagem, severidade):
            setattr(contagem, severidade, getattr(contagem, severidade) + 1)
        else:
            contagem.DESCONHECIDA += 1

    return schemas.ResumoResposta(
        ativo_id=ativo.id,
        ativo_nome=ativo.nome,
        ativo_versao=ativo.versao,
        total_cves=len(vulnerabilidades),
        por_severidade=contagem,
    )
