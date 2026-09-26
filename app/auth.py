"""
Autenticação simples via API Key para proteger rotas de escrita
(POST, PUT, DELETE).

Se a variável de ambiente WRITE_API_KEY não estiver definida, a proteção
fica desabilitada (útil para rodar o MVP localmente sem configuração
extra). Quando definida, o cliente deve enviar o header:

    X-API-Key: <valor de WRITE_API_KEY>
"""
import os

from fastapi import Header, HTTPException, status

WRITE_API_KEY = os.getenv("WRITE_API_KEY")


def exigir_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if WRITE_API_KEY is None:
        # Autenticação desabilitada: nenhuma chave configurada no ambiente.
        return
    if x_api_key != WRITE_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key ausente ou inválida. Envie o header X-API-Key.",
        )
