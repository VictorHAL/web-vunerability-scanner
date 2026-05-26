from schemas import CheckResult, CheckStatus, RiskLevel


def check_https(url: str) -> CheckResult:
    if url.startswith("https://"):
        return CheckResult(
            item="Protocolo HTTPS",
            descricao="A aplicação utiliza HTTPS, garantindo criptografia dos dados em trânsito.",
            status=CheckStatus.OK,
            risco=None,
            recomendacao=None,
        )
    return CheckResult(
        item="Protocolo HTTPS",
        descricao="A aplicação utiliza HTTP sem criptografia. Dados trafegam em texto puro.",
        status=CheckStatus.FALHOU,
        risco=RiskLevel.ALTO,
        recomendacao="Ative HTTPS no servidor e redirecione todo tráfego HTTP para HTTPS.",
    )
