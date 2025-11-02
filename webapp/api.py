"""FastAPI service exposing DoubleThink analysis."""
from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, model_validator

from doublethink.html_analyzer import analyze_html
from doublethink.reporting import result_to_dict
from doublethink.rules import RuleBook, default_rulebook
from doublethink.url_analyzer import analyze_url

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


class AnalyzeRequest(BaseModel):
    """Request schema for the analysis endpoint."""

    mode: Literal["url", "file"] = Field(description="Type of analysis to run")
    target: Optional[str] = Field(
        default=None, description="URL string or filesystem path depending on mode"
    )
    content: Optional[str] = Field(
        default=None,
        description="Raw HTML content to analyze when operating in file mode",
    )
    origin: Optional[str] = Field(
        default=None,
        description="Expected origin domain used for HTML analysis",
    )

    @model_validator(mode="after")
    def _validate_payload(self) -> "AnalyzeRequest":
        if self.mode == "url" and not self.target:
            raise ValueError("'target' must be provided when mode is 'url'.")
        if self.mode == "file" and not (self.content or self.target):
            raise ValueError("Provide either 'content' or 'target' when mode is 'file'.")
        return self


class SampleInfo(BaseModel):
    """Metadata describing demo samples available via the API."""

    id: str
    label: str
    mode: Literal["url", "file"]


class SamplePayload(BaseModel):
    """Payload returned when a specific sample is requested."""

    id: str
    mode: Literal["url", "file"]
    label: str
    target: Optional[str] = None
    content: Optional[str] = None


def _load_rulebook() -> RuleBook:
    return default_rulebook()


def _resolve_sample_files() -> list[SampleInfo]:
    entries: list[SampleInfo] = []
    if not SAMPLES_DIR.exists():
        return entries
    descriptions = {
        "benign_url.txt": "Benign login page URL",
        "homograph_url.txt": "Punycode homograph example",
        "typosquat_url.txt": "Typosquatted brand domain",
        "phish_login.html": "Suspicious login form HTML",
    }
    for item in sorted(SAMPLES_DIR.iterdir()):
        if not item.is_file():
            continue
        suffix = item.suffix.lower()
        if suffix not in {".txt", ".html", ".htm"}:
            continue
        mode: Literal["url", "file"] = "file" if suffix in {".html", ".htm"} else "url"
        label = descriptions.get(item.name, item.stem.replace("_", " ").title())
        entries.append(SampleInfo(id=item.name, label=label, mode=mode))
    return entries


def _load_sample(name: str) -> SamplePayload:
    path = SAMPLES_DIR / name
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(name)
    suffix = path.suffix.lower()
    mode: Literal["url", "file"] = "file" if suffix in {".html", ".htm"} else "url"
    label = name.replace("_", " ")
    payload = SamplePayload(id=name, mode=mode, label=label)
    if mode == "url":
        payload.target = path.read_text(encoding="utf-8").strip()
    else:
        payload.content = path.read_text(encoding="utf-8")
    return payload


def _analyze_file_content(content: str, rulebook: RuleBook, origin: Optional[str]) -> dict:
    with NamedTemporaryFile("w", delete=False, suffix=".html", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        temp_path = Path(handle.name)
    try:
        result = analyze_html(temp_path, rulebook, origin_domain=origin)
    finally:
        temp_path.unlink(missing_ok=True)
    return result_to_dict(result)


def _analyze_file_path(path_str: str, rulebook: RuleBook, origin: Optional[str]) -> dict:
    path = Path(path_str)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(path_str)
    result = analyze_html(path, rulebook, origin_domain=origin)
    return result_to_dict(result)


def _analyze_url(target: str, rulebook: RuleBook) -> dict:
    result = analyze_url(target, rulebook)
    return result_to_dict(result)


app = FastAPI(title="DoubleThink API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def healthcheck() -> dict:
    return {"status": "ok"}


@app.get("/samples", response_model=list[SampleInfo])
def list_samples() -> list[SampleInfo]:
    return _resolve_sample_files()


@app.get("/samples/{sample_id}", response_model=SamplePayload)
def get_sample(sample_id: str) -> SamplePayload:
    try:
        return _load_sample(sample_id)
    except FileNotFoundError as exc:  # noqa: BLE001
        raise HTTPException(status_code=404, detail=f"Sample not found: {sample_id}") from exc


@app.post("/analyze")
def analyze(request: AnalyzeRequest) -> dict:
    rulebook = _load_rulebook()
    try:
        if request.mode == "url":
            assert request.target is not None
            result = _analyze_url(request.target, rulebook)
        elif request.content:
            result = _analyze_file_content(request.content, rulebook, request.origin)
        else:
            assert request.target is not None
            result = _analyze_file_path(request.target, rulebook, request.origin)
    except FileNotFoundError as exc:  # noqa: BLE001
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    matches = result.get("matches", [])
    breakdown = [
        {
            "rule_id": match.get("rule_id"),
            "title": match.get("title"),
            "weight": match.get("weight"),
            "message": match.get("message"),
        }
        for match in matches
    ]

    return {
        "result": result,
        "breakdown": breakdown,
    }
