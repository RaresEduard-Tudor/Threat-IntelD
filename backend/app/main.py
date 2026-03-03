from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from datetime import datetime, timezone
import asyncio

from .checks.safe_browsing import check_safe_browsing
from .checks.domain_age import check_domain_age
from .checks.ssl_certificate import check_ssl_certificate
from .scoring import compute_score

app = FastAPI(
    title="Threat Intelligence Dashboard API",
    description="Analyze URLs for malware, phishing, domain age risk, and SSL validity.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    url: HttpUrl


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    target = str(request.url)

    safe_browsing_result, domain_age_result, ssl_result = await asyncio.gather(
        check_safe_browsing(target),
        check_domain_age(target),
        check_ssl_certificate(target),
    )

    threat_score, assessment = compute_score(safe_browsing_result, domain_age_result, ssl_result)

    return {
        "target_url": target,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "threat_score": threat_score,
        "assessment": assessment,
        "checks": {
            "safe_browsing": safe_browsing_result,
            "domain_age": domain_age_result,
            "ssl_certificate": ssl_result,
        },
    }
