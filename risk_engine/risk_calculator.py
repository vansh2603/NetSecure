
def calculate_risk(findings):
    if not findings:
        return 0.0

    scores = []

    for finding in findings:
        try:
            score = float(finding.get("score", 0.0))
        except (TypeError, ValueError):
            score = 0.0

        scores.append(max(0.0, min(10.0, score)))

    return round(max(scores), 1)


def get_risk_level(score):
    score = float(score)

    if score < 0 or score > 10:
        raise ValueError("Risk score must be between 0 and 10")

    if score < 3:
        return "Low"
    elif score < 6:
        return "Medium"
    elif score < 8:
        return "High"
    else:
        return "Critical"
