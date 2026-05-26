from schemas import CheckResult, CheckStatus, RiskLevel


def check_cookies(cookies: dict) -> list[CheckResult]:
    results = []

    if not cookies:
        results.append(CheckResult(
            item="Cookies",
            descricao="Nenhum cookie foi identificado na resposta.",
            status=CheckStatus.OK,
            risco=None,
            recomendacao=None,
        ))
        return results

    for name, cookie in cookies.items():
        # HttpOnly
        http_only = cookie.has_nonstandard_attr("HttpOnly") or getattr(cookie, "_rest", {}).get("HttpOnly") is not None

        # Secure
        secure = cookie.secure

        # SameSite
        samesite = cookie.get_nonstandard_attr("SameSite") or getattr(cookie, "_rest", {}).get("SameSite")

        if not http_only:
            results.append(CheckResult(
                item=f"Cookie '{name}' — HttpOnly ausente",
                descricao=f"O cookie '{name}' pode ser acessado via JavaScript, tornando-o vulnerável a ataques XSS.",
                status=CheckStatus.FALHOU,
                risco=RiskLevel.ALTO,
                recomendacao=f"Adicione a flag HttpOnly ao cookie '{name}': Set-Cookie: {name}=valor; HttpOnly",
            ))

        if not secure:
            results.append(CheckResult(
                item=f"Cookie '{name}' — Secure ausente",
                descricao=f"O cookie '{name}' pode ser transmitido via HTTP, expondo-o a interceptação.",
                status=CheckStatus.FALHOU,
                risco=RiskLevel.ALTO,
                recomendacao=f"Adicione a flag Secure ao cookie '{name}': Set-Cookie: {name}=valor; Secure",
            ))

        if not samesite:
            results.append(CheckResult(
                item=f"Cookie '{name}' — SameSite ausente",
                descricao=f"O cookie '{name}' está vulnerável a ataques CSRF.",
                status=CheckStatus.FALHOU,
                risco=RiskLevel.MEDIO,
                recomendacao=f"Adicione SameSite ao cookie '{name}': Set-Cookie: {name}=valor; SameSite=Strict",
            ))

        if http_only and secure and samesite:
            results.append(CheckResult(
                item=f"Cookie '{name}'",
                descricao=f"O cookie '{name}' está configurado corretamente com HttpOnly, Secure e SameSite.",
                status=CheckStatus.OK,
                risco=None,
                recomendacao=None,
            ))

    return results
