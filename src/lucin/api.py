"""Lucin API — RESTful service for agent security scanning and scoring.

Endpoints:
    POST /v1/scan          — Scan agent code/config for vulnerabilities
    POST /v1/score         — Score a single agent action for anomaly
    POST /v1/redteam       — Run red team attacks against an agent API
    GET  /v1/health        — Health check
    GET  /v1/rules         — List all detection rules

This is what turns Lucin from a CLI tool into a platform:
- Web dashboards call this API
- CI/CD systems integrate via HTTP
- Other security tools consume our risk scores
- Enterprise deployments at scale

Run with:
    uvicorn lucin.api:app --host 0.0.0.0 --port 8080

Or via CLI:
    lucin serve --port 8080
"""

import os
import tempfile
import time
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from lucin import __version__
from lucin.behavioral.features import AgentAction, extract_features
from lucin.behavioral.scoring import BehavioralScorer
from lucin.scanner import scan_target
from lucin.scoring import calculate_security_score, score_label

# === RATE LIMITING ===

class RateLimiter:
    """Simple in-memory rate limiter for API protection."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: dict[str, list[float]] = {}

    def is_allowed(self, client_id: str = "default") -> bool:
        """Check if a request is allowed under the rate limit."""
        now = time.time()
        if client_id not in self._requests:
            self._requests[client_id] = []

        # Remove expired entries
        self._requests[client_id] = [
            t for t in self._requests[client_id] if now - t < self.window
        ]

        if len(self._requests[client_id]) >= self.max_requests:
            return False

        self._requests[client_id].append(now)
        return True


_rate_limiter = RateLimiter(max_requests=100, window_seconds=60)


# === APP SETUP ===

app = FastAPI(
    title="Lucin API",
    description="AI Agent Security Scanner — Find what your agents can do that they shouldn't.",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Wildcard origin + allow_credentials=True is the exact AG-CORS pattern this
# product warns users about — Starlette reflects the request's Origin header
# in that combination, which is worse than a plain wildcard (any site can make
# credentialed requests). Default to same-origin-only; widen via env var.
_allowed_origins = [
    o.strip() for o in os.environ.get("LUCIN_API_ALLOWED_ORIGINS", "").split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=bool(_allowed_origins),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global behavioral scorer (maintains state across requests)
_scorer = BehavioralScorer()


# === REQUEST/RESPONSE MODELS ===

class ScanRequest(BaseModel):
    """Request to scan agent code or configuration."""
    code: str = Field(None, description="Python source code to scan")
    config: dict = Field(None, description="MCP/OpenAI JSON config to scan")
    framework: str = Field("auto", description="Framework hint: langchain, crewai, autogen, mcp, auto")


class ScanResponse(BaseModel):
    """Scan results."""
    score: int = Field(description="Security score 0-100")
    score_label: str = Field(description="Human-readable score label")
    findings_count: int
    critical: int
    high: int
    medium: int
    low: int
    findings: list[dict]
    agents: list[dict]
    scan_duration_ms: float


class ScoreRequest(BaseModel):
    """Request to score a single agent action for behavioral anomaly."""
    agent_id: str = Field(description="Unique agent identifier")
    tool: str = Field(description="Tool name that was called")
    params: dict = Field(default_factory=dict, description="Tool call parameters")
    timestamp: str = Field(None, description="ISO 8601 timestamp (or uses current time)")
    session_id: str = Field("default", description="Session identifier")
    user_id: str = Field("", description="User who triggered the action")


class ScoreResponse(BaseModel):
    """Behavioral anomaly score for a single action."""
    score: int = Field(description="Risk score 0-99")
    action: str = Field(description="allow, alert, escalate, or block")
    confidence: float = Field(description="Model confidence 0.0-1.0")
    factors: list[str] = Field(description="Contributing factors for this score")
    baseline_complete: bool = Field(description="Whether baseline learning is complete")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str = __version__
    agents_baselined: int = 0
    uptime_seconds: float = 0


class RuleInfo(BaseModel):
    """Information about a detection rule."""
    id: str
    title: str
    severity: str
    owasp_ref: str
    description: str


# === ENDPOINTS ===

_start_time = time.time()


@app.get("/v1/health", response_model=HealthResponse)
async def health():
    """Health check — verify the API is running."""
    return HealthResponse(
        status="healthy",
        version=__version__,
        agents_baselined=_scorer.baseline_count,
        uptime_seconds=time.time() - _start_time,
    )


@app.post("/v1/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    """Scan agent code or configuration for security vulnerabilities.

    Submit Python source code or a JSON config, and receive
    a security assessment with findings, score, and recommendations.
    """
    if not request.code and not request.config:
        raise HTTPException(status_code=400, detail="Provide either 'code' or 'config'")

    # Write to temp file for scanning
    with tempfile.TemporaryDirectory() as tmpdir:
        target_path = Path(tmpdir)

        if request.code:
            code_file = target_path / "agent.py"
            code_file.write_text(request.code)
        elif request.config:
            import json
            config_file = target_path / "mcp.json"
            config_file.write_text(json.dumps(request.config))

        # Run scan
        start = time.time()
        result = scan_target(target_path, framework=request.framework)
        duration = (time.time() - start) * 1000

    # Calculate score
    score = calculate_security_score(result)

    return ScanResponse(
        score=score,
        score_label=score_label(score),
        findings_count=len(result.findings),
        critical=result.critical_count,
        high=result.high_count,
        medium=result.medium_count,
        low=result.low_count,
        findings=[f.model_dump() for f in result.findings],
        agents=[a.model_dump() for a in result.agents],
        scan_duration_ms=duration,
    )


@app.post("/v1/score", response_model=ScoreResponse)
async def score_action(request: ScoreRequest):
    """Score a single agent action for behavioral anomaly.

    Send each agent action as it happens. The system learns
    what's normal during the first 50 actions per agent,
    then scores every subsequent action 0-99.

    Use this for real-time monitoring integration.
    """
    # Parse timestamp
    if request.timestamp:
        try:
            ts = datetime.fromisoformat(request.timestamp.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.now()
    else:
        ts = datetime.now()

    # Create action
    action = AgentAction(
        timestamp=ts,
        agent_id=request.agent_id,
        session_id=request.session_id,
        action_type="tool_call",
        tool_name=request.tool,
        parameters=request.params,
        user_id=request.user_id,
    )

    # Extract features
    features = extract_features(action)

    # Check if baseline is complete for this agent
    baseline_complete = _scorer._baselines.get(request.agent_id) is not None and \
        _scorer._baselines.get(request.agent_id, type("", (), {"observation_count": 0})()).observation_count > 50

    # Learn + Score
    _scorer.learn(features)

    if baseline_complete:
        risk = _scorer.score(features)
        return ScoreResponse(
            score=risk.score,
            action=risk.action_threshold,
            confidence=risk.confidence,
            factors=risk.contributing_factors,
            baseline_complete=True,
        )
    else:
        # Still learning — return zero score
        count = _scorer._baselines.get(request.agent_id, type("", (), {"observation_count": 0})()).observation_count
        return ScoreResponse(
            score=0,
            action="allow",
            confidence=0.0,
            factors=[f"Baseline learning: {count}/50 actions observed"],
            baseline_complete=False,
        )


@app.get("/v1/rules", response_model=list[RuleInfo])
async def list_rules():
    """List all documented detection rules, derived from the single source of
    truth (lucin.rule_docs.RULE_CATALOG) rather than a hand-maintained copy —
    a second list here previously drifted stale and cited the wrong OWASP
    taxonomy (Web Top 10 codes instead of ASI codes)."""
    from lucin.owasp import owasp_ref as _owasp_ref
    from lucin.rule_docs import RULE_CATALOG

    return [
        RuleInfo(
            id=rid,
            title=entry.get("title", rid),
            severity=str(entry.get("severity", "")).lower(),
            owasp_ref=_owasp_ref(rid),
            description=entry.get("description", ""),
        )
        for rid, entry in sorted(RULE_CATALOG.items())
    ]
