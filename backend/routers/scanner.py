from fastapi import APIRouter, HTTPException
import httpx

from schemas import ScanRequest, ScanResponse, CheckStatus
from scanner import (
    check_security_headers,
    check_cookies,
    check_https,
    calculate_score,
)

router = APIRouter(tags=["Scanner"])

BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
TIMEOUT = 10.0


def _validate_url(url: str):
    """Bloqueia requisições para hosts internos (prevenção de SSRF)."""
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    if host in BLOCKED_HOSTS or host.startswith("192.168.") or host.startswith("10."):
        raise HTTPException(
            status_code=400,
            detail="URL interna não permitida por razões de segurança (SSRF prevention).",
        )


@router.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    url = str(request.url)
    _validate_url(url)

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=TIMEOUT,
            verify=False,  # permite scanear sites com cert expirado
        ) as client:
            response = await client.get(url)
    except httpx.TimeoutException:
        raise HTTPException(status_code=408, detail="Timeout ao acessar a URL alvo.")
    except httpx.RequestError as e:
        raise HTTPException(status_code=400, detail=f"Erro ao acessar a URL: {str(e)}")

    checks = []
    checks.append(check_https(url))
    checks.extend(check_security_headers(dict(response.headers)))
    checks.extend(check_cookies(response.cookies))

    score = calculate_score(checks)
    passou = sum(1 for c in checks if c.status == CheckStatus.OK)
    falhou = sum(1 for c in checks if c.status == CheckStatus.FALHOU)

    return ScanResponse(
        url=url,
        score=score,
        total_checks=len(checks),
        passou=passou,
        falhou=falhou,
        checks=checks,
    )
