from pydantic import BaseModel, HttpUrl
from typing import List, Optional
from enum import Enum


class RiskLevel(str, Enum):
    ALTO = "ALTO"
    MEDIO = "MEDIO"
    BAIXO = "BAIXO"
    NENHUM = "NENHUM"


class CheckStatus(str, Enum):
    OK = "OK"
    FALHOU = "FALHOU"
    AVISO = "AVISO"


class CheckResult(BaseModel):
    item: str
    descricao: str
    status: CheckStatus
    risco: Optional[RiskLevel]
    recomendacao: Optional[str]


class ScanRequest(BaseModel):
    url: HttpUrl


class ScanResponse(BaseModel):
    url: str
    score: int
    total_checks: int
    passou: int
    falhou: int
    checks: List[CheckResult]
