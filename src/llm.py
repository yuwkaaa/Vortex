from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Literal, MutableMapping

from dotenv import load_dotenv

from src.metrics import record_llm_call


LLMProvider = Literal["openrouter", "vertexai_adc", "byteplus"]

_VERTEXAI_MAAS_MODEL_ALIASES = {
    "glm-5": "zai-org/glm-5-maas",
    "glm-5-maas": "zai-org/glm-5-maas",
    "glm-4.7": "zai-org/glm-4.7-maas",
    "glm-4.7-maas": "zai-org/glm-4.7-maas",
}


@dataclass(frozen=True)
class OpenRouterConfig:
    api_key: str
    base_url: str
    model: str


@dataclass(frozen=True)
class BytePlusConfig:
    api_key: str
    base_url: str
    model: str


@dataclass(frozen=True)
class VertexAIADCConfig:
    project: str
    location: str
    model: str
    base_url: str
    access_token: str


def _getenv(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def normalize_llm_provider(provider: str) -> LLMProvider:
    canonical = provider.strip().lower()
    if canonical in {"openrouter", "openai", "openai_compatible"}:
        return "openrouter"
    if canonical in {"byteplus", "modelark", "ark", "bytedance"}:
        return "byteplus"
    if canonical in {"vertexai", "vertexai_adc", "vertex"}:
        return "vertexai_adc"
    raise RuntimeError(
        f"Unsupported LLM_PROVIDER={canonical!r}. "
        "Use 'openrouter', 'vertexai_adc', or 'byteplus'."
    )


def configure_llm_environment(
    *,
    env: MutableMapping[str, str] | None = None,
    provider: str = "",
    model: str = "",
    byteplus_glm5: bool = False,
    isolate_provider_secrets: bool = True,
) -> MutableMapping[str, str]:
    """Apply CLI-level LLM provider/model choices to an environment mapping."""
    target = os.environ if env is None else env
    requested_provider = provider.strip()
    requested_model = model.strip()

    if byteplus_glm5:
        if requested_provider and normalize_llm_provider(requested_provider) != "byteplus":
            raise RuntimeError("--byteplus-glm5 cannot be combined with a non-byteplus --llm-provider.")
        if requested_model and requested_model != "glm-5":
            raise RuntimeError("--byteplus-glm5 cannot be combined with a non-glm-5 --llm-model.")
        requested_provider = "byteplus"
        requested_model = "glm-5"
        target.setdefault("BYTEPLUS_MIN_MAX_TOKENS", "4096")

    if requested_provider:
        canonical = normalize_llm_provider(requested_provider)
        target["LLM_PROVIDER"] = canonical
        if isolate_provider_secrets:
            if canonical != "byteplus":
                target.pop("BYTEPLUS_API_KEY", None)
                target.pop("ARK_API_KEY", None)
            if canonical != "openrouter":
                target.pop("OPENROUTER_API_KEY", None)
    else:
        canonical = load_llm_provider()

    if requested_model:
        if canonical == "byteplus":
            target["BYTEPLUS_MODEL"] = requested_model
        elif canonical == "vertexai_adc":
            target["VERTEXAI_MODEL"] = requested_model
        else:
            target["OPENROUTER_MODEL"] = requested_model

    return target


def load_llm_provider() -> LLMProvider:
    load_dotenv()
    provider = _getenv("LLM_PROVIDER").lower()
    if not provider:
        has_google_project = bool(_getenv("VERTEXAI_PROJECT") or _getenv("GOOGLE_CLOUD_PROJECT"))
        has_openrouter_key = bool(_getenv("OPENROUTER_API_KEY"))
        if has_google_project and not has_openrouter_key:
            return "vertexai_adc"
        return "openrouter"
    return normalize_llm_provider(provider)


def load_openrouter_config() -> OpenRouterConfig:
    """
    Loads OpenRouter settings for an OpenAI-compatible API client.

    Environment variables:
    - OPENROUTER_API_KEY
    - OPENROUTER_BASE_URL
    - OPENROUTER_MODEL
    """
    load_dotenv()

    api_key = _getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("Missing OPENROUTER_API_KEY.")

    base_url = _getenv("OPENROUTER_BASE_URL")
    if not base_url:
        raise RuntimeError("Missing OPENROUTER_BASE_URL.")

    model = _getenv("OPENROUTER_MODEL")
    if not model:
        raise RuntimeError("Missing OPENROUTER_MODEL.")

    return OpenRouterConfig(api_key=api_key, base_url=base_url, model=model)


def load_byteplus_config() -> BytePlusConfig:
    """
    Loads BytePlus ModelArk settings for an OpenAI-compatible API client.

    Environment variables:
    - BYTEPLUS_API_KEY or ARK_API_KEY
    - BYTEPLUS_BASE_URL or ARK_BASE_URL, default:
      https://ark.ap-southeast.bytepluses.com/api/coding/v3
    - BYTEPLUS_MODEL or ARK_MODEL, default: glm-4.7
    """
    load_dotenv()

    api_key = _getenv("BYTEPLUS_API_KEY") or _getenv("ARK_API_KEY")
    if not api_key:
        raise RuntimeError("Missing BYTEPLUS_API_KEY or ARK_API_KEY.")

    base_url = (
        _getenv("BYTEPLUS_BASE_URL")
        or _getenv("ARK_BASE_URL")
        or "https://ark.ap-southeast.bytepluses.com/api/coding/v3"
    ).rstrip("/")

    model = _getenv("BYTEPLUS_MODEL") or _getenv("ARK_MODEL") or "glm-4.7"

    return BytePlusConfig(api_key=api_key, base_url=base_url, model=model)


def _load_adc_access_token() -> str:
    """
    Load a Google Cloud access token from Application Default Credentials.

    ADC can come from `gcloud auth application-default login`, a service-account
    JSON pointed to by GOOGLE_APPLICATION_CREDENTIALS, or workload identity.
    """
    try:
        import google.auth
        import google.auth.transport.requests
    except ImportError as exc:
        raise RuntimeError(
            "Missing google-auth. Install dependencies with `pip install -r requirements.txt`."
        ) from exc

    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    credentials.refresh(google.auth.transport.requests.Request())
    return credentials.token


def _vertexai_base_url(*, project: str, location: str, endpoint_id: str) -> str:
    api_version = _getenv("VERTEXAI_API_VERSION", "v1")
    host = _getenv("VERTEXAI_API_HOST")
    if not host:
        if endpoint_id == "openapi":
            host = "https://aiplatform.googleapis.com"
        else:
            host = f"https://{location}-aiplatform.googleapis.com"
    host = host.rstrip("/")
    return (
        f"{host}/{api_version}/projects/{project}/locations/{location}"
        f"/endpoints/{endpoint_id}"
    )


def _normalize_vertexai_model(model: str) -> str:
    normalized = model.strip()
    return _VERTEXAI_MAAS_MODEL_ALIASES.get(normalized.lower(), normalized)


def load_vertexai_adc_config() -> VertexAIADCConfig:
    """
    Loads Vertex AI OpenAI-compatible settings using Google ADC.

    Environment variables:
    - VERTEXAI_PROJECT: required GCP project id.
    - VERTEXAI_LOCATION: default `global`.
    - VERTEXAI_MODEL: default `glm-5`.
    - VERTEXAI_ENDPOINT_ID: default `openapi`; use a deployed endpoint id for
      self-deployed Model Garden models such as GLM-5.
    - VERTEXAI_BASE_URL: optional full override.
    """
    load_dotenv()

    project = _getenv("VERTEXAI_PROJECT") or _getenv("GOOGLE_CLOUD_PROJECT")
    if not project:
        raise RuntimeError("Missing VERTEXAI_PROJECT or GOOGLE_CLOUD_PROJECT.")

    location = _getenv("VERTEXAI_LOCATION") or _getenv("GOOGLE_VERTEX_LOCATION", "global")
    model = _normalize_vertexai_model(_getenv("VERTEXAI_MODEL", "glm-5"))
    endpoint_id = _getenv("VERTEXAI_ENDPOINT_ID", "openapi")
    base_url = _getenv("VERTEXAI_BASE_URL") or _vertexai_base_url(
        project=project,
        location=location,
        endpoint_id=endpoint_id,
    )
    access_token = _load_adc_access_token()
    return VertexAIADCConfig(
        project=project,
        location=location,
        model=model,
        base_url=base_url,
        access_token=access_token,
    )


def _max_tokens(provider: LLMProvider, max_tokens: int | None) -> int:
    if provider == "byteplus":
        minimum = int(_getenv("BYTEPLUS_MIN_MAX_TOKENS", _getenv("ARK_MIN_MAX_TOKENS", "4096")))
        if max_tokens is not None:
            return max(int(max_tokens), minimum)
        return int(_getenv("BYTEPLUS_MAX_TOKENS", _getenv("ARK_MAX_TOKENS", str(minimum))))
    if provider == "vertexai_adc":
        minimum = int(_getenv("VERTEXAI_MIN_MAX_TOKENS", "4096"))
        if max_tokens is not None:
            return max(int(max_tokens), minimum)
        return int(_getenv("VERTEXAI_MAX_TOKENS", str(minimum)))
    if max_tokens is not None:
        return max_tokens
    return int(_getenv("OPENROUTER_MAX_TOKENS", "4096"))


def _llm_timeout() -> float:
    return float(_getenv("LLM_TIMEOUT_SECONDS", "60"))


def _llm_max_retries() -> int:
    return int(_getenv("LLM_MAX_RETRIES", "1"))


def _chat_openai_class() -> Any:
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise RuntimeError(
            "Missing langchain-openai. Install dependencies with `pip install -r requirements.txt`."
        ) from exc
    return ChatOpenAI


def get_llm(max_tokens: int | None = None) -> Any:
    provider = load_llm_provider()
    resolved_max_tokens = _max_tokens(provider, max_tokens)
    ChatOpenAI = _chat_openai_class()

    if provider == "vertexai_adc":
        cfg = load_vertexai_adc_config()
        llm = ChatOpenAI(
            model=cfg.model,
            api_key=cfg.access_token,
            base_url=cfg.base_url,
            temperature=0.2,
            max_tokens=resolved_max_tokens,
            timeout=_llm_timeout(),
            max_retries=_llm_max_retries(),
        )
        return MeteredLLM(llm, provider=provider, model=cfg.model)

    if provider == "byteplus":
        cfg = load_byteplus_config()
        llm = ChatOpenAI(
            model=cfg.model,
            api_key=cfg.api_key,
            base_url=cfg.base_url,
            temperature=0.2,
            max_tokens=resolved_max_tokens,
            timeout=_llm_timeout(),
            max_retries=_llm_max_retries(),
        )
        return MeteredLLM(llm, provider=provider, model=cfg.model)

    cfg = load_openrouter_config()
    llm = ChatOpenAI(
        model=cfg.model,
        api_key=cfg.api_key,
        base_url=cfg.base_url,
        temperature=0.2,
        max_tokens=resolved_max_tokens,
        timeout=_llm_timeout(),
        max_retries=_llm_max_retries(),
    )
    return MeteredLLM(llm, provider=provider, model=cfg.model)


class MeteredLLM:
    """Thin wrapper that records latency and token usage for LangChain chat models."""

    def __init__(self, wrapped: Any, *, provider: str, model: str) -> None:
        self._wrapped = wrapped
        self._provider = provider
        self._model = model

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)

    def bind_tools(self, *args: Any, **kwargs: Any) -> "MeteredLLM":
        bound = self._wrapped.bind_tools(*args, **kwargs)
        return MeteredLLM(bound, provider=self._provider, model=self._model)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        start = time.monotonic()
        try:
            response = self._wrapped.invoke(*args, **kwargs)
        except Exception as exc:
            record_llm_call(
                provider=self._provider,
                model=self._model,
                elapsed_seconds=time.monotonic() - start,
                error=exc,
            )
            raise
        record_llm_call(
            provider=self._provider,
            model=self._model,
            elapsed_seconds=time.monotonic() - start,
            response=response,
        )
        return response
