from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from domain_intel import analyze_domain, normalize_domain


class AnalyzeRequest(BaseModel):
    domain: str = Field(..., min_length=1)
    active_scan: bool = False


app = FastAPI(title="Domain Intel 360 API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(payload: AnalyzeRequest):
    domain = normalize_domain(payload.domain)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

    try:
        return analyze_domain(domain=domain, use_scan=payload.active_scan)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc
