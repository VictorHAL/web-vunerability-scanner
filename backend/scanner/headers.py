from schemas import CheckResult, CheckStatus, RiskLevel


SECURITY_HEADERS = [
    {
        "header": "content-security-policy",
        "item": "Content-Security-Policy (CSP)",
        "descricao": "Previne ataques XSS ao definir fontes confiáveis de conteúdo.",
        "risco": RiskLevel.ALTO,
        "recomendacao": "Adicione o header Content-Security-Policy com uma política restritiva. Ex: Content-Security-Policy: default-src 'self'",
    },
    {
        "header": "strict-transport-security",
        "item": "Strict-Transport-Security (HSTS)",
        "descricao": "Força conexões HTTPS, prevenindo ataques de downgrade.",
        "risco": RiskLevel.ALTO,
        "recomendacao": "Adicione: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
        "header": "x-frame-options",
        "item": "X-Frame-Options",
        "descricao": "Previne ataques de clickjacking bloqueando iframes não autorizados.",
        "risco": RiskLevel.MEDIO,
        "recomendacao": "Adicione: X-Frame-Options: DENY ou X-Frame-Options: SAMEORIGIN",
    },
    {
        "header": "x-content-type-options",
        "item": "X-Content-Type-Options",
        "descricao": "Previne MIME sniffing pelo navegador.",
        "risco": RiskLevel.MEDIO,
        "recomendacao": "Adicione: X-Content-Type-Options: nosniff",
    },
    {
        "header": "referrer-policy",
        "item": "Referrer-Policy",
        "descricao": "Controla quais informações de referência são enviadas nas requisições.",
        "risco": RiskLevel.BAIXO,
        "recomendacao": "Adicione: Referrer-Policy: no-referrer ou strict-origin-when-cross-origin",
    },
    {
        "header": "permissions-policy",
        "item": "Permissions-Policy",
        "descricao": "Controla acesso a funcionalidades do navegador como câmera e microfone.",
        "risco": RiskLevel.BAIXO,
        "recomendacao": "Adicione: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
]

EXPOSED_HEADERS = [
    {
        "header": "server",
        "item": "Exposição do header Server",
        "descricao": "Revela informações sobre o servidor web utilizado.",
        "risco": RiskLevel.BAIXO,
        "recomendacao": "Remova ou oculte o header Server nas configurações do servidor web.",
    },
    {
        "header": "x-powered-by",
        "item": "Exposição do header X-Powered-By",
        "descricao": "Revela a linguagem/framework utilizado na aplicação.",
        "risco": RiskLevel.BAIXO,
        "recomendacao": "Remova o header X-Powered-By. Em Express.js: app.disable('x-powered-by')",
    },
]


def check_security_headers(headers: dict) -> list[CheckResult]:
    results = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for check in SECURITY_HEADERS:
        presente = check["header"] in headers_lower
        results.append(CheckResult(
            item=check["item"],
            descricao=check["descricao"],
            status=CheckStatus.OK if presente else CheckStatus.FALHOU,
            risco=None if presente else check["risco"],
            recomendacao=None if presente else check["recomendacao"],
        ))

    for check in EXPOSED_HEADERS:
        exposto = check["header"] in headers_lower
        results.append(CheckResult(
            item=check["item"],
            descricao=check["descricao"],
            status=CheckStatus.FALHOU if exposto else CheckStatus.OK,
            risco=check["risco"] if exposto else None,
            recomendacao=check["recomendacao"] if exposto else None,
        ))

    return results
