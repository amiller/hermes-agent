"""Shared auxiliary OpenAI client for cheap/fast side tasks.

Provides a single resolution chain so every consumer (context compression,
session search, web extraction, vision analysis, browser vision) picks up
the best available backend without duplicating fallback logic.

Resolution order for text tasks:
  1. OpenRouter  (OPENROUTER_API_KEY)
  2. Nous Portal (~/.hermes/auth.json active provider)
  3. Custom endpoint (OPENAI_BASE_URL + OPENAI_API_KEY)
  4. Codex OAuth (Responses API via chatgpt.com with gpt-5.3-codex,
     wrapped to look like a chat.completions client)
  5. Anthropic (ANTHROPIC_TOKEN or ANTHROPIC_API_KEY, wrapped to look
     like a chat.completions client)
  6. Direct API-key providers (z.ai/GLM, Kimi/Moonshot, MiniMax, MiniMax-CN)
     — checked via PROVIDER_REGISTRY entries with auth_type='api_key'
  7. None

Resolution order for vision/multimodal tasks:
  1. OpenRouter
  2. Nous Portal
  3. Anthropic (Claude supports vision natively)
  4. None
"""

import json
import logging
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

from openai import OpenAI

from hermes_constants import OPENROUTER_BASE_URL

logger = logging.getLogger(__name__)

# Default auxiliary models for direct API-key providers (cheap/fast for side tasks)
_API_KEY_PROVIDER_AUX_MODELS: Dict[str, str] = {
    "zai": "glm-4.5-flash",
    "kimi-coding": "kimi-k2-turbo-preview",
    "minimax": "MiniMax-M2.5-highspeed",
    "minimax-cn": "MiniMax-M2.5-highspeed",
}

# OpenRouter app attribution headers
_OR_HEADERS = {
    "HTTP-Referer": "https://github.com/NousResearch/hermes-agent",
    "X-OpenRouter-Title": "Hermes Agent",
    "X-OpenRouter-Categories": "productivity,cli-agent",
}

# Nous Portal extra_body for product attribution.
# Callers should pass this as extra_body in chat.completions.create()
# when the auxiliary client is backed by Nous Portal.
NOUS_EXTRA_BODY = {"tags": ["product=hermes-agent"]}

# Set at resolve time — True if the auxiliary client points to Nous Portal
auxiliary_is_nous: bool = False

# Default auxiliary models per provider
_OPENROUTER_MODEL = "google/gemini-3-flash-preview"
_NOUS_MODEL = "gemini-3-flash"
_NOUS_DEFAULT_BASE_URL = "https://inference-api.nousresearch.com/v1"
_AUTH_JSON_PATH = Path.home() / ".hermes" / "auth.json"

# Codex fallback: uses the Responses API (the only endpoint the Codex
# OAuth token can access) with a fast model for auxiliary tasks.
_CODEX_AUX_MODEL = "gpt-5.3-codex"
_CODEX_AUX_BASE_URL = "https://chatgpt.com/backend-api/codex"


# ── Codex Responses → chat.completions adapter ─────────────────────────────
# All auxiliary consumers call client.chat.completions.create(**kwargs) and
# read response.choices[0].message.content. This adapter translates those
# calls to the Codex Responses API so callers don't need any changes.

class _CodexCompletionsAdapter:
    """Drop-in shim that accepts chat.completions.create() kwargs and
    routes them through the Codex Responses streaming API."""

    def __init__(self, real_client: OpenAI, model: str):
        self._client = real_client
        self._model = model

    def create(self, **kwargs) -> Any:
        messages = kwargs.get("messages", [])
        model = kwargs.get("model", self._model)
        temperature = kwargs.get("temperature")

        # Separate system/instructions from conversation messages
        instructions = "You are a helpful assistant."
        input_msgs: List[Dict[str, Any]] = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content") or ""
            if role == "system":
                instructions = content
            else:
                input_msgs.append({"role": role, "content": content})

        resp_kwargs: Dict[str, Any] = {
            "model": model,
            "instructions": instructions,
            "input": input_msgs or [{"role": "user", "content": ""}],
            "stream": True,
            "store": False,
        }

        max_tokens = kwargs.get("max_output_tokens") or kwargs.get("max_completion_tokens") or kwargs.get("max_tokens")
        if max_tokens is not None:
            resp_kwargs["max_output_tokens"] = int(max_tokens)
        if temperature is not None:
            resp_kwargs["temperature"] = temperature

        # Tools support for flush_memories and similar callers
        tools = kwargs.get("tools")
        if tools:
            converted = []
            for t in tools:
                fn = t.get("function", {}) if isinstance(t, dict) else {}
                name = fn.get("name")
                if not name:
                    continue
                converted.append({
                    "type": "function",
                    "name": name,
                    "description": fn.get("description", ""),
                    "parameters": fn.get("parameters", {}),
                })
            if converted:
                resp_kwargs["tools"] = converted

        # Stream and collect the response
        text_parts: List[str] = []
        tool_calls_raw: List[Any] = []
        usage = None

        try:
            with self._client.responses.stream(**resp_kwargs) as stream:
                for _event in stream:
                    pass
                final = stream.get_final_response()

            # Extract text and tool calls from the Responses output
            for item in getattr(final, "output", []):
                item_type = getattr(item, "type", None)
                if item_type == "message":
                    for part in getattr(item, "content", []):
                        ptype = getattr(part, "type", None)
                        if ptype in ("output_text", "text"):
                            text_parts.append(getattr(part, "text", ""))
                elif item_type == "function_call":
                    tool_calls_raw.append(SimpleNamespace(
                        id=getattr(item, "call_id", ""),
                        type="function",
                        function=SimpleNamespace(
                            name=getattr(item, "name", ""),
                            arguments=getattr(item, "arguments", "{}"),
                        ),
                    ))

            resp_usage = getattr(final, "usage", None)
            if resp_usage:
                usage = SimpleNamespace(
                    prompt_tokens=getattr(resp_usage, "input_tokens", 0),
                    completion_tokens=getattr(resp_usage, "output_tokens", 0),
                    total_tokens=getattr(resp_usage, "total_tokens", 0),
                )
        except Exception as exc:
            logger.debug("Codex auxiliary Responses API call failed: %s", exc)
            raise

        content = "".join(text_parts).strip() or None

        # Build a response that looks like chat.completions
        message = SimpleNamespace(
            role="assistant",
            content=content,
            tool_calls=tool_calls_raw or None,
        )
        choice = SimpleNamespace(
            index=0,
            message=message,
            finish_reason="stop" if not tool_calls_raw else "tool_calls",
        )
        return SimpleNamespace(
            choices=[choice],
            model=model,
            usage=usage,
        )


class _CodexChatShim:
    """Wraps the adapter to provide client.chat.completions.create()."""

    def __init__(self, adapter: _CodexCompletionsAdapter):
        self.completions = adapter


class CodexAuxiliaryClient:
    """OpenAI-client-compatible wrapper that routes through Codex Responses API.

    Consumers can call client.chat.completions.create(**kwargs) as normal.
    Also exposes .api_key and .base_url for introspection by async wrappers.
    """

    def __init__(self, real_client: OpenAI, model: str):
        self._real_client = real_client
        adapter = _CodexCompletionsAdapter(real_client, model)
        self.chat = _CodexChatShim(adapter)
        self.api_key = real_client.api_key
        self.base_url = real_client.base_url

    def close(self):
        self._real_client.close()


class _AsyncCodexCompletionsAdapter:
    """Async version of the Codex Responses adapter.

    Wraps the sync adapter via asyncio.to_thread() so async consumers
    (web_tools, session_search) can await it as normal.
    """

    def __init__(self, sync_adapter: _CodexCompletionsAdapter):
        self._sync = sync_adapter

    async def create(self, **kwargs) -> Any:
        import asyncio
        return await asyncio.to_thread(self._sync.create, **kwargs)


class _AsyncCodexChatShim:
    def __init__(self, adapter: _AsyncCodexCompletionsAdapter):
        self.completions = adapter


class AsyncCodexAuxiliaryClient:
    """Async-compatible wrapper matching AsyncOpenAI.chat.completions.create()."""

    def __init__(self, sync_wrapper: "CodexAuxiliaryClient"):
        sync_adapter = sync_wrapper.chat.completions
        async_adapter = _AsyncCodexCompletionsAdapter(sync_adapter)
        self.chat = _AsyncCodexChatShim(async_adapter)
        self.api_key = sync_wrapper.api_key
        self.base_url = sync_wrapper.base_url


_ANTHROPIC_AUX_MODEL = "claude-haiku-4-5-20251001"


def _read_anthropic_token() -> Optional[str]:
    """Return an Anthropic API key or OAuth token if available."""
    for var in ("ANTHROPIC_TOKEN", "ANTHROPIC_API_KEY"):
        val = os.getenv(var, "").strip()
        if val:
            return val
    return None


class _AnthropicCompletionsAdapter:
    """Shim that accepts chat.completions.create() kwargs and routes
    them through the Anthropic Messages API."""

    def __init__(self, client, model: str):
        self._client = client
        self._model = model

    def create(self, **kwargs) -> Any:
        from agent.anthropic_adapter import (
            convert_messages_to_anthropic,
            convert_tools_to_anthropic,
        )

        messages = kwargs.get("messages", [])
        model = kwargs.get("model", self._model)
        system, ant_messages = convert_messages_to_anthropic(messages)
        tools = convert_tools_to_anthropic(kwargs.get("tools") or [])
        max_tokens = kwargs.get("max_tokens") or kwargs.get("max_completion_tokens") or 4096

        api_kwargs: Dict[str, Any] = {
            "model": model,
            "messages": ant_messages,
            "max_tokens": max_tokens,
        }
        if system:
            api_kwargs["system"] = system
        if tools:
            api_kwargs["tools"] = tools

        resp = self._client.messages.create(**api_kwargs)

        # Build OpenAI-shaped response
        text_parts = []
        tool_calls_raw = []
        for block in resp.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls_raw.append(SimpleNamespace(
                    id=block.id,
                    type="function",
                    function=SimpleNamespace(
                        name=block.name,
                        arguments=json.dumps(block.input),
                    ),
                ))

        content = "\n".join(text_parts).strip() or None
        message = SimpleNamespace(
            role="assistant",
            content=content,
            tool_calls=tool_calls_raw or None,
        )
        choice = SimpleNamespace(
            index=0,
            message=message,
            finish_reason="tool_calls" if tool_calls_raw else "stop",
        )
        usage = SimpleNamespace(
            prompt_tokens=resp.usage.input_tokens,
            completion_tokens=resp.usage.output_tokens,
            total_tokens=resp.usage.input_tokens + resp.usage.output_tokens,
        )
        return SimpleNamespace(choices=[choice], model=model, usage=usage)


class _AnthropicChatShim:
    def __init__(self, adapter: _AnthropicCompletionsAdapter):
        self.completions = adapter


class AnthropicAuxiliaryClient:
    """OpenAI-client-compatible wrapper for Anthropic Messages API.

    Consumers call client.chat.completions.create(**kwargs) as normal.
    """

    def __init__(self, client, model: str):
        self._client = client
        adapter = _AnthropicCompletionsAdapter(client, model)
        self.chat = _AnthropicChatShim(adapter)
        self.api_key = "anthropic"
        self.base_url = "https://api.anthropic.com"

    def close(self):
        self._client.close()


class _AsyncAnthropicCompletionsAdapter:
    def __init__(self, sync_adapter: _AnthropicCompletionsAdapter):
        self._sync = sync_adapter

    async def create(self, **kwargs) -> Any:
        import asyncio
        return await asyncio.to_thread(self._sync.create, **kwargs)


class _AsyncAnthropicChatShim:
    def __init__(self, adapter: _AsyncAnthropicCompletionsAdapter):
        self.completions = adapter


class AsyncAnthropicAuxiliaryClient:
    def __init__(self, sync_wrapper: AnthropicAuxiliaryClient):
        sync_adapter = sync_wrapper.chat.completions
        async_adapter = _AsyncAnthropicCompletionsAdapter(sync_adapter)
        self.chat = _AsyncAnthropicChatShim(async_adapter)
        self.api_key = sync_wrapper.api_key
        self.base_url = sync_wrapper.base_url


def _read_nous_auth() -> Optional[dict]:
    """Read and validate ~/.hermes/auth.json for an active Nous provider.

    Returns the provider state dict if Nous is active with tokens,
    otherwise None.
    """
    try:
        if not _AUTH_JSON_PATH.is_file():
            return None
        data = json.loads(_AUTH_JSON_PATH.read_text())
        if data.get("active_provider") != "nous":
            return None
        provider = data.get("providers", {}).get("nous", {})
        # Must have at least an access_token or agent_key
        if not provider.get("agent_key") and not provider.get("access_token"):
            return None
        return provider
    except Exception as exc:
        logger.debug("Could not read Nous auth: %s", exc)
        return None


def _nous_api_key(provider: dict) -> str:
    """Extract the best API key from a Nous provider state dict."""
    return provider.get("agent_key") or provider.get("access_token", "")


def _nous_base_url() -> str:
    """Resolve the Nous inference base URL from env or default."""
    return os.getenv("NOUS_INFERENCE_BASE_URL", _NOUS_DEFAULT_BASE_URL)


def _read_codex_access_token() -> Optional[str]:
    """Read a valid Codex OAuth access token from Hermes auth store (~/.hermes/auth.json)."""
    try:
        from hermes_cli.auth import _read_codex_tokens
        data = _read_codex_tokens()
        tokens = data.get("tokens", {})
        access_token = tokens.get("access_token")
        if isinstance(access_token, str) and access_token.strip():
            return access_token.strip()
        return None
    except Exception as exc:
        logger.debug("Could not read Codex auth for auxiliary client: %s", exc)
        return None


def _resolve_api_key_provider() -> Tuple[Optional[OpenAI], Optional[str]]:
    """Try each API-key provider in PROVIDER_REGISTRY order.

    Returns (client, model) for the first provider whose env var is set,
    or (None, None) if none are configured.
    """
    try:
        from hermes_cli.auth import PROVIDER_REGISTRY
    except ImportError:
        logger.debug("Could not import PROVIDER_REGISTRY for API-key fallback")
        return None, None

    for provider_id, pconfig in PROVIDER_REGISTRY.items():
        if pconfig.auth_type != "api_key":
            continue
        # Check if any of the provider's env vars are set
        api_key = ""
        for env_var in pconfig.api_key_env_vars:
            val = os.getenv(env_var, "").strip()
            if val:
                api_key = val
                break
        if not api_key:
            continue
        # Resolve base URL (with optional env-var override)
        # Kimi Code keys (sk-kimi-) need api.kimi.com/coding/v1
        env_url = ""
        if pconfig.base_url_env_var:
            env_url = os.getenv(pconfig.base_url_env_var, "").strip()
        if env_url:
            base_url = env_url.rstrip("/")
        elif provider_id == "kimi-coding" and api_key.startswith("sk-kimi-"):
            base_url = "https://api.kimi.com/coding/v1"
        else:
            base_url = pconfig.inference_base_url
        model = _API_KEY_PROVIDER_AUX_MODELS.get(provider_id, "default")
        logger.debug("Auxiliary text client: %s (%s)", pconfig.name, model)
        extra = {}
        if "api.kimi.com" in base_url.lower():
            extra["default_headers"] = {"User-Agent": "KimiCLI/1.0"}
        return OpenAI(api_key=api_key, base_url=base_url, **extra), model

    return None, None


# ── Public API ──────────────────────────────────────────────────────────────

def get_text_auxiliary_client() -> Tuple[Optional[OpenAI], Optional[str]]:
    """Return (client, model_slug) for text-only auxiliary tasks.

    Falls through OpenRouter -> Nous Portal -> custom endpoint -> Codex OAuth
    -> direct API-key providers -> (None, None).
    """
    # 1. OpenRouter
    or_key = os.getenv("OPENROUTER_API_KEY")
    if or_key:
        logger.debug("Auxiliary text client: OpenRouter")
        return OpenAI(api_key=or_key, base_url=OPENROUTER_BASE_URL,
                       default_headers=_OR_HEADERS), _OPENROUTER_MODEL

    # 2. Nous Portal
    nous = _read_nous_auth()
    if nous:
        global auxiliary_is_nous
        auxiliary_is_nous = True
        logger.debug("Auxiliary text client: Nous Portal")
        return (
            OpenAI(api_key=_nous_api_key(nous), base_url=_nous_base_url()),
            _NOUS_MODEL,
        )

    # 3. Custom endpoint (both base URL and key must be set)
    custom_base = os.getenv("OPENAI_BASE_URL")
    custom_key = os.getenv("OPENAI_API_KEY")
    if custom_base and custom_key:
        model = os.getenv("OPENAI_MODEL") or os.getenv("LLM_MODEL") or "gpt-4o-mini"
        logger.debug("Auxiliary text client: custom endpoint (%s)", model)
        return OpenAI(api_key=custom_key, base_url=custom_base), model

    # 4. Codex OAuth -- uses the Responses API (only endpoint the token
    # can access), wrapped to look like a chat.completions client.
    codex_token = _read_codex_access_token()
    if codex_token:
        logger.debug("Auxiliary text client: Codex OAuth (%s via Responses API)", _CODEX_AUX_MODEL)
        real_client = OpenAI(api_key=codex_token, base_url=_CODEX_AUX_BASE_URL)
        return CodexAuxiliaryClient(real_client, _CODEX_AUX_MODEL), _CODEX_AUX_MODEL

    # 5. Anthropic (ANTHROPIC_TOKEN or ANTHROPIC_API_KEY)
    ant_token = _read_anthropic_token()
    if ant_token:
        from agent.anthropic_adapter import build_anthropic_client
        logger.debug("Auxiliary text client: Anthropic (%s)", _ANTHROPIC_AUX_MODEL)
        client = build_anthropic_client(ant_token)
        return AnthropicAuxiliaryClient(client, _ANTHROPIC_AUX_MODEL), _ANTHROPIC_AUX_MODEL

    # 6. Direct API-key providers (z.ai/GLM, Kimi/Moonshot, MiniMax, etc.)
    api_client, api_model = _resolve_api_key_provider()
    if api_client is not None:
        return api_client, api_model

    # 7. Nothing available
    logger.debug("Auxiliary text client: none available")
    return None, None


def get_async_text_auxiliary_client():
    """Return (async_client, model_slug) for async consumers.

    For standard providers returns (AsyncOpenAI, model). For Codex returns
    (AsyncCodexAuxiliaryClient, model) which wraps the Responses API.
    Returns (None, None) when no provider is available.
    """
    from openai import AsyncOpenAI

    sync_client, model = get_text_auxiliary_client()
    if sync_client is None:
        return None, None

    if isinstance(sync_client, CodexAuxiliaryClient):
        return AsyncCodexAuxiliaryClient(sync_client), model

    if isinstance(sync_client, AnthropicAuxiliaryClient):
        return AsyncAnthropicAuxiliaryClient(sync_client), model

    async_kwargs = {
        "api_key": sync_client.api_key,
        "base_url": str(sync_client.base_url),
    }
    if "openrouter" in str(sync_client.base_url).lower():
        async_kwargs["default_headers"] = dict(_OR_HEADERS)
    elif "api.kimi.com" in str(sync_client.base_url).lower():
        async_kwargs["default_headers"] = {"User-Agent": "KimiCLI/1.0"}
    return AsyncOpenAI(**async_kwargs), model


def get_vision_auxiliary_client() -> Tuple[Optional[OpenAI], Optional[str]]:
    """Return (client, model_slug) for vision/multimodal auxiliary tasks.

    Only OpenRouter and Nous Portal qualify — custom endpoints cannot
    substitute for Gemini multimodal.
    """
    # 1. OpenRouter
    or_key = os.getenv("OPENROUTER_API_KEY")
    if or_key:
        logger.debug("Auxiliary vision client: OpenRouter")
        return OpenAI(api_key=or_key, base_url=OPENROUTER_BASE_URL,
                       default_headers=_OR_HEADERS), _OPENROUTER_MODEL

    # 2. Nous Portal
    nous = _read_nous_auth()
    if nous:
        logger.debug("Auxiliary vision client: Nous Portal")
        return (
            OpenAI(api_key=_nous_api_key(nous), base_url=_nous_base_url()),
            _NOUS_MODEL,
        )

    # 3. Anthropic (Claude supports vision natively)
    ant_token = _read_anthropic_token()
    if ant_token:
        from agent.anthropic_adapter import build_anthropic_client
        logger.debug("Auxiliary vision client: Anthropic (%s)", _ANTHROPIC_AUX_MODEL)
        client = build_anthropic_client(ant_token)
        return AnthropicAuxiliaryClient(client, _ANTHROPIC_AUX_MODEL), _ANTHROPIC_AUX_MODEL

    # 4. Nothing suitable
    logger.debug("Auxiliary vision client: none available")
    return None, None


def get_auxiliary_extra_body() -> dict:
    """Return extra_body kwargs for auxiliary API calls.
    
    Includes Nous Portal product tags when the auxiliary client is backed
    by Nous Portal. Returns empty dict otherwise.
    """
    return dict(NOUS_EXTRA_BODY) if auxiliary_is_nous else {}


def auxiliary_max_tokens_param(value: int) -> dict:
    """Return the correct max tokens kwarg for the auxiliary client's provider.
    
    OpenRouter and local models use 'max_tokens'. Direct OpenAI with newer
    models (gpt-4o, o-series, gpt-5+) requires 'max_completion_tokens'.
    The Codex adapter translates max_tokens internally, so we use max_tokens
    for it as well.
    """
    custom_base = os.getenv("OPENAI_BASE_URL", "")
    or_key = os.getenv("OPENROUTER_API_KEY")
    # Only use max_completion_tokens for direct OpenAI custom endpoints
    if (not or_key
            and _read_nous_auth() is None
            and "api.openai.com" in custom_base.lower()):
        return {"max_completion_tokens": value}
    return {"max_tokens": value}
