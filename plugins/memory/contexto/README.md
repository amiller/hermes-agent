# Contexto memory plugin (self-hosted)

Wires the self-hosted Contexto memory engine into hermes-agent's `MemoryProvider` interface.

> Self-hosted only. The hosted `api.getcontexto.com` API has a completely different surface and is not supported by this plugin.

## What it does

- **Per-turn ingest:** every (user, assistant) pair is sent to `/v1/ingest`. The server runs LLM extraction and shards components across episodic, semantic, and procedural sectors.
- **Pre-turn recall:** before each turn, queries `/v1/search` with the user message and injects the top working-memory hits into the system prompt.
- **Tool exposure:** model can call `contexto_search` to look up prior knowledge explicitly.

## Scoping

- **Agent slug:** one per hermes profile (`agent_identity`). All sessions of the same profile pool into the same agent's memory.
- **User id:** passed through to Contexto for per-user scoping within an agent.

## Install

Bring up the Contexto self-hosted stack first (port 4010 by default), then:

```bash
pip install "contexto @ git+https://github.com/amiller/contexto.git#subdirectory=clients/python"
```

## Activate

In your hermes config:

```yaml
memory:
  provider: contexto
```

## Env vars

- `CONTEXTO_BASE_URL` (optional — defaults to `http://localhost:4010`)
