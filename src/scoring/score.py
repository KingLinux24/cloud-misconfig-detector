from typing import List
from src.utils.schema import Finding

SEV_SCORE = {"critical": 100, "high": 80, "medium": 50, "low": 20, "info": 5}

def score_findings(findings: List[Finding]) -> list[dict]:
    out = []
    for f in findings:
        base = SEV_SCORE.get(f.severity, 10)

        cat = f.category.lower()
        boost = 0
        if "public" in cat:
            boost += 10
        if "data" in cat:
            boost += 5

        # Safe compatibility fallback for Pydantic v1 and v2
        data = f.model_dump() if hasattr(f, "model_dump") else f.dict()

        out.append({
            **data,
            "risk_score": min(100, base + boost)
        })

    out.sort(key=lambda x: x["risk_score"], reverse=True)
    return out
