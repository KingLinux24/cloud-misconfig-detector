from fastapi import FastAPI, HTTPException
from pathlib import Path
from typing import List, Dict, Any
from pydantic import BaseModel
from src.utils.schema import Finding

REPORT_PATH = Path("data/processed/report.json")

app = FastAPI(title="Cloud Misconfiguration Detector", version="1.0")

# Define the response schema for Swagger documentation
class ReportResponse(BaseModel):
    resource_count: int
    finding_count: int
    findings: List[Dict[str, Any]]  # Or List[Finding] if you want granular schemas documented!

@app.get("/report", response_model=ReportResponse)
def report():
    if not REPORT_PATH.exists():
        raise HTTPException(status_code=404, detail="Run pipeline first: python src/utils/run.py")
    
    import json
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))
