from schemas import CheckResult, CheckStatus, RiskLevel

# Peso de cada nível de risco na penalização do score
RISK_PENALTY = {
    RiskLevel.ALTO: 15,
    RiskLevel.MEDIO: 8,
    RiskLevel.BAIXO: 3,
}


def calculate_score(checks: list[CheckResult]) -> int:
    score = 100
    for check in checks:
        if check.status == CheckStatus.FALHOU and check.risco:
            score -= RISK_PENALTY.get(check.risco, 0)
    return max(0, score)
