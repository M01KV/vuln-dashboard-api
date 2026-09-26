"""
Integração com a NVD API (National Vulnerability Database).

Documentação oficial: https://nvd.nist.gov/developers/vulnerabilities
Endpoint consumido:  GET https://services.nvd.nist.gov/rest/json/cves/2.0

A NVD é um serviço público e gratuito. Uma chave de API (NVD_API_KEY) é
opcional, mas recomendada: sem chave o limite é de ~5 requisições / 30s,
com chave o limite sobe para ~50 requisições / 30s.
"""
import os
import time
from datetime import datetime, timezone
from typing import Optional

import httpx

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")  # opcional
NVD_TIMEOUT_SECONDS = float(os.getenv("NVD_TIMEOUT_SECONDS", "10"))
CACHE_TTL_SECONDS = int(os.getenv("NVD_CACHE_TTL_SECONDS", "900"))  # 15 min
RESULTS_PER_PAGE = int(os.getenv("NVD_RESULTS_PER_PAGE", "20"))


class NvdError(Exception):
    """Erro genérico ao consultar a NVD."""


class NvdTimeoutError(NvdError):
    """A NVD não respondeu dentro do tempo limite."""


class NvdRateLimitError(NvdError):
    """A NVD recusou a requisição por excesso de chamadas (HTTP 403/429)."""


class NvdIndisponivelError(NvdError):
    """A NVD retornou um erro de servidor (5xx) ou de conexão."""


# Cache simples em memória: {termo_busca: (timestamp, payload)}
# Suficiente para um MVP; em produção usar Redis ou similar.
_cache: dict[str, tuple[float, dict]] = {}


def _extrair_do_cache(termo: str) -> Optional[dict]:
    entrada = _cache.get(termo)
    if not entrada:
        return None
    timestamp, payload = entrada
    if time.time() - timestamp > CACHE_TTL_SECONDS:
        _cache.pop(termo, None)
        return None
    return payload


def _salvar_no_cache(termo: str, payload: dict) -> None:
    _cache[termo] = (time.time(), payload)


def _severidade_e_score(metrics: dict) -> tuple[Optional[float], str]:
    """Extrai (score_cvss, severidade) priorizando CVSS v3.1 > v3.0 > v2."""
    for chave in ("cvssMetricV31", "cvssMetricV30"):
        bloco = metrics.get(chave)
        if bloco:
            dados = bloco[0]["cvssData"]
            severidade = dados.get("baseSeverity", "DESCONHECIDA")
            return dados.get("baseScore"), severidade

    bloco_v2 = metrics.get("cvssMetricV2")
    if bloco_v2:
        item = bloco_v2[0]
        score = item["cvssData"].get("baseScore")
        # CVSS v2 não traz baseSeverity pronto; classificamos manualmente.
        severidade = item.get("baseSeverity")
        if not severidade and score is not None:
            if score >= 7:
                severidade = "HIGH"
            elif score >= 4:
                severidade = "MEDIUM"
            else:
                severidade = "LOW"
        return score, severidade or "DESCONHECIDA"

    return None, "DESCONHECIDA"


def _descricao_em_ingles(descricoes: list[dict]) -> str:
    for item in descricoes:
        if item.get("lang") == "en":
            return item.get("value", "")
    return descricoes[0].get("value", "") if descricoes else "Sem descrição disponível."


def _mapear_item(item_nvd: dict) -> dict:
    cve = item_nvd["cve"]
    score, severidade = _severidade_e_score(cve.get("metrics", {}))
    data_publicacao = cve.get("published")

    return {
        "cve_id": cve["id"],
        "descricao": _descricao_em_ingles(cve.get("descriptions", [])),
        "score_cvss": score,
        "severidade": severidade,
        "data_publicacao": datetime.fromisoformat(data_publicacao) if data_publicacao else None,
    }


async def buscar_cves(termo_busca: str, usar_cache: bool = True) -> tuple[list[dict], bool]:
    """
    Consulta a NVD API por CVEs relacionados ao termo (ex.: "nginx 1.18").

    Retorna uma tupla (lista_de_cves, veio_do_cache).

    Levanta:
        NvdTimeoutError    - timeout na chamada
        NvdRateLimitError  - HTTP 403/429 (limite de requisições excedido)
        NvdIndisponivelError - erro 5xx ou falha de conexão
    """
    if usar_cache:
        cache_hit = _extrair_do_cache(termo_busca)
        if cache_hit is not None:
            return cache_hit["vulnerabilidades"], True

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {
        "keywordSearch": termo_busca,
        "resultsPerPage": RESULTS_PER_PAGE,
    }

    try:
        async with httpx.AsyncClient(timeout=NVD_TIMEOUT_SECONDS) as client:
            resposta = await client.get(NVD_BASE_URL, params=params, headers=headers)
    except httpx.TimeoutException as exc:
        raise NvdTimeoutError(f"Timeout ao consultar a NVD para '{termo_busca}'.") from exc
    except httpx.RequestError as exc:
        raise NvdIndisponivelError(f"Falha de conexão com a NVD: {exc}") from exc

    if resposta.status_code in (403, 429):
        raise NvdRateLimitError(
            "Limite de requisições da NVD excedido. Aguarde alguns segundos e tente novamente."
        )
    if resposta.status_code >= 500:
        raise NvdIndisponivelError(f"NVD retornou erro {resposta.status_code}.")
    resposta.raise_for_status()

    corpo = resposta.json()
    vulnerabilidades = [_mapear_item(v) for v in corpo.get("vulnerabilities", [])]

    _salvar_no_cache(termo_busca, {"vulnerabilidades": vulnerabilidades})
    return vulnerabilidades, False
