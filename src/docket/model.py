"""The one path from this tool to a model, and the recording that makes a run re-derivable.

Three obligations, taken from the sibling projects because they were learned the expensive way:

**Exactly one attempt, and failures are returned rather than raised.** A retry hidden inside an
adapter breaks the cost accounting and the record of how many attempts a disposition took. A
failure is a result with a cost and a duration; the caller decides what to do with it.

**The seam is provider-neutral and the adapter is the only thing that knows a wire format.** There
is one adapter here and it speaks the OpenAI-compatible chat completions API, which OpenRouter also
speaks, so a second provider is a base URL rather than a second code path.

**Every call is recorded at the seam, keyed by a hash of the canonical request.** That is what lets
an evidence record be re-derived months later with no key and no network: the recording is an
input, the replay refuses on a miss rather than reaching for the provider, and a test runs the
whole path with the environment variable unset. The format is one JSON object per line carrying
the provider, the model *as the provider returned it*, the request hash, the request, and the
response.

**No SDK.** The request is JSON over HTTPS and `urllib` sends it. A tool whose first phase needs no
model should not make every installation carry a provider client.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pathlib import Path

from docket.hashing import content_hash

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_MODEL",
    "FailureReason",
    "ModelFailure",
    "ModelOutcome",
    "ModelRequest",
    "ModelSuccess",
    "OpenAICompatibleModel",
    "RecordingModel",
    "ReplayModel",
    "StructuredModel",
    "canonical_request_hash",
    "read_recording",
]

DEFAULT_BASE_URL: Final = "https://openrouter.ai/api/v1"
DEFAULT_MODEL: Final = "openai/gpt-5.1"


class FailureReason(StrEnum):
    """Why one attempt produced no validated object.

    The division that matters is between a failure the same call might survive and one it will
    not, and that is a property of the reason rather than of the caller's patience.
    """

    SCHEMA_VALIDATION_FAILURE = "schema_validation_failure"
    TRANSIENT_PROVIDER_FAILURE = "transient_provider_failure"
    TIMEOUT = "timeout"
    CONNECTION_FAILURE = "connection_failure"
    INVALID_REQUEST = "invalid_request"
    AUTHENTICATION_FAILURE = "authentication_failure"
    NOT_RECORDED = "not_recorded"
    """Replay was asked for a request the recording does not hold. Never falls back to the
    network: a replay that silently reaches a provider is not a replay."""


_RETRYABLE: Final[frozenset[FailureReason]] = frozenset(
    {
        FailureReason.SCHEMA_VALIDATION_FAILURE,
        FailureReason.TRANSIENT_PROVIDER_FAILURE,
        FailureReason.TIMEOUT,
        FailureReason.CONNECTION_FAILURE,
    }
)


@dataclass(frozen=True, slots=True)
class ModelRequest:
    """One request, in the seam's own terms.

    `system` is application-owned text and `user` carries whatever the claim said, already fenced
    by the caller. The seam does not fence, because fencing needs to know what is quoted and what
    is instruction, and that is the caller's knowledge.
    """

    system: str
    user: str
    schema_name: str
    schema: dict[str, Any]
    max_output_tokens: int = 4_000
    timeout_seconds: float = 300.0


@dataclass(frozen=True, slots=True)
class ModelUsage:
    """What one attempt consumed."""

    model: str
    """The model as the provider reported it, which is not always the model requested."""

    input_tokens: int = 0
    output_tokens: int = 0
    duration_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class ModelSuccess:
    """A response that parsed as the requested object."""

    value: dict[str, Any]
    usage: ModelUsage

    @property
    def succeeded(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class ModelFailure:
    """One attempt that produced no object, and everything known about why."""

    reason: FailureReason
    message: str
    usage: ModelUsage
    raw_output: str | None = None
    """What the model said, when it said anything. Kept for debugging and untrusted like any
    other model output."""

    @property
    def succeeded(self) -> bool:
        return False

    @property
    def retryable(self) -> bool:
        return self.reason in _RETRYABLE


type ModelOutcome = ModelSuccess | ModelFailure


@runtime_checkable
class StructuredModel(Protocol):
    """The only path from application code to a model. One method, one attempt, never raises."""

    @property
    def name(self) -> str:
        """What produced the output, for the record."""
        ...

    def generate(self, request: ModelRequest) -> ModelOutcome:
        """Make exactly one attempt. Return a failure rather than raising for provider
        conditions."""
        ...


def canonical_request_hash(request: ModelRequest, *, model: str) -> str:
    """The key a recording is stored under.

    Canonical JSON with sorted keys, so two structurally identical requests hash the same however
    they were built. The model is part of the key because the same prompt to a different model is
    a different request, and replaying one as the other would silently mislabel the evidence.
    """
    payload = json.dumps(
        {
            "model": model,
            "system": request.system,
            "user": request.user,
            "schema_name": request.schema_name,
            "schema": request.schema,
            "max_output_tokens": request.max_output_tokens,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return content_hash(payload.encode("utf-8"))


def _extract_object(text: str) -> dict[str, Any] | None:
    """The JSON object in a response, tolerating a fenced block around it."""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = [line for line in stripped.splitlines() if not line.startswith("```")]
        stripped = "\n".join(lines).strip()
    try:
        loaded = json.loads(stripped)
    except json.JSONDecodeError:
        start, end = stripped.find("{"), stripped.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            loaded = json.loads(stripped[start : end + 1])
        except json.JSONDecodeError:
            return None
    return loaded if isinstance(loaded, dict) else None


@dataclass
class OpenAICompatibleModel:
    """The adapter. Speaks chat completions over HTTPS with no SDK.

    One attempt. Every provider condition becomes a `ModelFailure` with a reason the caller can
    route on, and the raw body survives a parse failure.
    """

    model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL
    api_key_env: str = "OPENROUTER_API_KEY"

    @property
    def name(self) -> str:
        return self.model

    def generate(self, request: ModelRequest) -> ModelOutcome:
        key = os.environ.get(self.api_key_env, "")
        started = time.monotonic()
        if not key:
            return ModelFailure(
                reason=FailureReason.AUTHENTICATION_FAILURE,
                message=f"{self.api_key_env} is not set",
                usage=ModelUsage(model=self.model),
            )

        body = json.dumps(
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": request.system},
                    {"role": "user", "content": request.user},
                ],
                "max_completion_tokens": request.max_output_tokens,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": request.schema_name,
                        "schema": request.schema,
                    },
                },
            }
        ).encode("utf-8")

        http = urllib.request.Request(  # noqa: S310 - the URL is configuration, not input
            f"{self.base_url.rstrip('/')}/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(http, timeout=request.timeout_seconds) as response:  # noqa: S310
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:2000]
            reason = (
                FailureReason.AUTHENTICATION_FAILURE
                if error.code in {401, 403}
                else FailureReason.TRANSIENT_PROVIDER_FAILURE
                if error.code in {408, 429} or error.code >= 500
                else FailureReason.INVALID_REQUEST
            )
            return ModelFailure(
                reason=reason,
                message=f"HTTP {error.code}: {detail}",
                usage=ModelUsage(model=self.model, duration_seconds=time.monotonic() - started),
            )
        except TimeoutError:
            return ModelFailure(
                reason=FailureReason.TIMEOUT,
                message=f"no response within {request.timeout_seconds}s",
                usage=ModelUsage(model=self.model, duration_seconds=time.monotonic() - started),
            )
        except (urllib.error.URLError, OSError) as error:
            return ModelFailure(
                reason=FailureReason.CONNECTION_FAILURE,
                message=str(error),
                usage=ModelUsage(model=self.model, duration_seconds=time.monotonic() - started),
            )

        duration = time.monotonic() - started
        usage_block = payload.get("usage") or {}
        usage = ModelUsage(
            model=str(payload.get("model") or self.model),
            input_tokens=int(usage_block.get("prompt_tokens") or 0),
            output_tokens=int(usage_block.get("completion_tokens") or 0),
            duration_seconds=duration,
        )

        choices = payload.get("choices") or []
        text = ""
        if choices:
            text = str((choices[0].get("message") or {}).get("content") or "")
        obj = _extract_object(text)
        if obj is None:
            return ModelFailure(
                reason=FailureReason.SCHEMA_VALIDATION_FAILURE,
                message="the response held no JSON object",
                usage=usage,
                raw_output=text or json.dumps(payload)[:2000],
            )
        return ModelSuccess(value=obj, usage=usage)


@dataclass
class RecordingModel:
    """Wraps a model and appends every successful call to a JSONL recording.

    The convention is the sibling project's: one object per line carrying the provider, the model
    as returned, the request hash, the request, and the response. A failure is not recorded,
    because a recording exists to make a successful run reproducible and a recorded failure would
    replay as one.
    """

    inner: StructuredModel
    path: Path
    provider: str = "openrouter"
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    """Appends are serialised so a batch assessing claims concurrently cannot interleave two
    JSON objects on one line."""

    @property
    def name(self) -> str:
        return self.inner.name

    def generate(self, request: ModelRequest) -> ModelOutcome:
        outcome = self.inner.generate(request)
        if not isinstance(outcome, ModelSuccess):
            return outcome
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(
            {
                "provider": self.provider,
                "model": outcome.usage.model,
                "request_hash": canonical_request_hash(request, model=self.inner.name),
                "request": {
                    "system": request.system,
                    "user": request.user,
                    "schema_name": request.schema_name,
                },
                "response": outcome.value,
                "usage": {
                    "input_tokens": outcome.usage.input_tokens,
                    "output_tokens": outcome.usage.output_tokens,
                },
            },
            sort_keys=True,
        )
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        return outcome


def read_recording(path: Path) -> dict[str, dict[str, Any]]:
    """Every recorded call, keyed by request hash. A later line wins over an earlier one."""
    entries: dict[str, dict[str, Any]] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        entry = json.loads(raw)
        entries[str(entry["request_hash"])] = entry
    return entries


@dataclass
class ReplayModel:
    """Serves recorded responses and never reaches the network.

    A request the recording does not hold is `NOT_RECORDED`, which is a failure the caller sees
    rather than a silent call to a provider. That refusal is what makes an offline re-derivation
    mean something.
    """

    entries: dict[str, dict[str, Any]]
    model: str = DEFAULT_MODEL
    served: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.model

    @classmethod
    def from_path(cls, path: Path, *, model: str = DEFAULT_MODEL) -> ReplayModel:
        return cls(entries=read_recording(path), model=model)

    def generate(self, request: ModelRequest) -> ModelOutcome:
        key = canonical_request_hash(request, model=self.model)
        entry = self.entries.get(key)
        if entry is None:
            return ModelFailure(
                reason=FailureReason.NOT_RECORDED,
                message=f"no recorded response for request {key}",
                usage=ModelUsage(model=self.model),
            )
        self.served.append(key)
        usage_block = entry.get("usage") or {}
        return ModelSuccess(
            value=dict(entry["response"]),
            usage=ModelUsage(
                model=str(entry.get("model") or self.model),
                input_tokens=int(usage_block.get("input_tokens") or 0),
                output_tokens=int(usage_block.get("output_tokens") or 0),
            ),
        )
