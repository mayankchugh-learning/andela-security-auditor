def calculate_risk_score(findings: list[dict]) -> tuple[int, str]:
    """Return (score, risk_level) for a list of finding dicts."""
    total = sum(f["points"] for f in findings)
    score = min(total, 100)

    if score == 0:
        level = "Clean"
    elif score <= 25:
        level = "Low Risk"
    elif score <= 50:
        level = "Medium Risk"
    elif score <= 75:
        level = "High Risk"
    else:
        level = "Critical Risk"

    return score, level
