from pydantic import BaseModel, Field
from typing import Dict, List, Any

class Finding(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    resource: Dict[str, Any]
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: str
    references: List[str] = Field(default_factory=list)
