# llm-warden — Design Spec

**Date:** 2026-06-04
**Status:** Approved design, pending implementation plan
**Repo:** new public repo `kavumahamza/llm-warden` (MIT license), scaffolded at `~/Desktop/llm-warden`

## 1. Purpose

A self-hostable guardrail gateway for LLM APIs, built as the flagship public
portfolio project for Kavuma Hamza's GitHub profile. It must turn the profile's
claims (TypeScript/Express backend, AI-agent safety, auth/rate limiting, PII
redaction, Docker/CI) into verifiable public code.

**Primary goal:** portfolio proof — optimized for a reviewer reading the repo.
Real adoption is a bonus. Scope is deliberately tight and finishable.

## 2. What it is

An HTTP gateway you point your app at instead of the LLM provider. Clients keep
their existing Anthropic or OpenAI SDKs and change only the `baseURL` plus a
warden virtual key. The gateway:

1. authenticates the caller (virtual API keys; optional HMAC signed requests)
2. enforces per-key token-bucket rate limits
3. runs **input guardrails** on the prompt (redact / block / flag)
4. forwards to the provider behind a circuit breaker
5. runs **stream guardrails** on the response as it streams — redacting PII
   inside SSE text deltas with chunk-boundary buffering
6. re-serializes the stream in the dialect the client spoke

### Positioning (from competitive research, 2026-06)

- Multi-provider routing is commoditized (LiteLLM, Portkey, OpenRouter,
  Helicone). **Do not lead with it.**
- The headline differentiator is the **`stream` guardrail stage**: LiteLLM's
  streaming PII hooks are broken on native passthrough (issues #9639, #22821);
  Portkey output guardrails run only after stream completion; Cloudflare
  moderates full prompts/responses; Bedrock buffers-then-scans. No OSS tool
  does correct per-delta redaction across both Anthropic and OpenAI SSE
  dialects.
- Second differentiator: **zero-dependency in-process guardrails** — no
  Presidio containers (LiteLLM), no enterprise plugin (Kong), one Docker image.
- We lose the raw-latency race to Go/Rust gateways (Bifrost, Helicone-RS) and
  say so; we compete on streaming-guardrail correctness, zero config, and
  security posture.
- The industry names two hook stages (input/output guardrails). We name three:
  **input / stream / output** — first-class.

## 3. Decisions locked during brainstorming

| Decision | Choice |
| --- | --- |
| Primary goal | Portfolio proof |
| Providers (v1) | Anthropic Messages API + OpenAI-compatible (covers Gemini/Groq/Ollama compat endpoints) |
| v1 guardrails | Auth + rate limiting; PII redaction + filters; SSE streaming filtering; secrets detection; basic prompt-injection heuristics |
| Deferred | Postgres audit log, eval/red-team harness (promptfoo), NER tier, Redis store |
| Stack | TypeScript + Express (matches profile claims) |
| Architecture | A: layered middleware pipeline over a normalized provider event stream (rejected: plugin kernel, proxy+policy service) |
| Done bar | Polished README + architecture diagram, vitest suite in GitHub Actions, published Docker image (GHCR), `docker compose up` demo |
| Persistence | None in v1. Keys + policies in `warden.yaml`; rate-limit state in-memory behind a `Store` interface |
| Name | `llm-warden` (plain "warden" collides with the Magento dev tool) |

## 4. Architecture

```
 Client app (unchanged Anthropic/OpenAI SDK, baseURL → warden)
    │  POST /v1/messages  |  POST /v1/chat/completions
    ▼
┌────────────────────────── llm-warden ──────────────────────────┐
│  HTTP layer (Express)                                          │
│   ├─ auth middleware        virtual keys (+ optional HMAC)     │
│   ├─ rate-limit middleware  token bucket per key               │
│   ▼                                                            │
│  Guardrail engine — input stage                                │
│   ├─ checks on full prompt: PII, secrets, injection, blocklist │
│   ▼                                                            │
│  Provider adapter (anthropic | openai-compat)                  │
│   ├─ circuit breaker wraps provider call                       │
│   ├─ parses provider SSE → NormalizedEvent stream              │
│   ▼                                                            │
│  Guardrail engine — stream stage (Transform over events)       │
│   ├─ boundary buffer + redaction on text deltas                │
│   ▼                                                            │
│  Adapter re-serializes events → client (SSE or JSON)           │
└────────────────────────────────────────────────────────────────┘
```

Non-streaming responses go through an **output stage** (same checks, whole
body) instead of the stream stage.

### Module layout

```
llm-warden/
├── src/
│   ├── server.ts              # Express wiring; routes → pipeline
│   ├── config/
│   │   ├── schema.ts          # zod schema for warden.yaml
│   │   └── load.ts            # load + validate; fail fast, precise errors
│   ├── auth/
│   │   ├── apiKey.ts          # virtual keys; SHA-256 hashed in config; constant-time compare
│   │   └── hmac.ts            # opt-in signed requests: timestamp ±300s + body sig + replay cache
│   ├── ratelimit/
│   │   ├── tokenBucket.ts     # pure math, no I/O
│   │   └── store.ts           # Store interface + InMemoryStore (Redis later)
│   ├── guardrails/
│   │   ├── engine.ts          # runs ordered checks per stage; aggregates verdicts
│   │   ├── types.ts           # Check, Verdict, Detection, stage defs
│   │   ├── detectors/
│   │   │   ├── pii.ts         # email, phone, card (Luhn), US SSN, IBAN (checksum),
│   │   │   │                  #   IP v4/v6, MAC, URL, crypto wallet
│   │   │   ├── secrets.ts     # AWS keys, GitHub tokens, generic API-key entropy patterns
│   │   │   └── injection.ts   # heuristics: known patterns, Unicode/encoding attacks
│   │   ├── blocklist.ts       # configurable term blocklist
│   │   └── streamFilter.ts    # boundary buffer + redaction over text deltas
│   ├── providers/
│   │   ├── types.ts           # NormalizedEvent union + ProviderAdapter interface
│   │   ├── anthropic.ts       # Messages API: named SSE events (message_start,
│   │   │                      #   content_block_delta, message_stop…)
│   │   └── openaiCompat.ts    # chat/completions: data:{choices:[{delta}]}…[DONE]
│   ├── resilience/
│   │   └── circuitBreaker.ts  # per-provider: closed → open → half-open
│   └── observability/
│       └── logger.ts          # structured pino; verdicts/metadata ONLY, never content
├── test/                      # vitest: unit, integration (mock provider), invariance suite
├── examples/                  # curl scripts + Anthropic/OpenAI SDK demo clients
├── warden.example.yaml
├── Dockerfile                 # multi-stage, distroless runtime
├── docker-compose.yaml        # warden + mock provider: instant local demo
└── .github/workflows/ci.yaml  # lint, typecheck, test, docker build; GHCR publish on tag
```

### Core interfaces

```ts
// providers/types.ts
type NormalizedEvent =
  | { type: 'message_start'; meta: ProviderMeta }
  | { type: 'text_delta'; text: string }
  | { type: 'tool_call_delta'; index: number; json: string }
  | { type: 'message_end'; usage: Usage; stopReason: string }
  | { type: 'provider_error'; error: ProviderError }

interface ProviderAdapter {
  buildRequest(incoming: GatewayRequest): ProviderRequest
  parseStream(body: ReadableStream): AsyncIterable<NormalizedEvent>
  serializeEvent(e: NormalizedEvent): string   // back to the client's dialect
  parseResponse(body: unknown): NormalizedMessage          // non-streaming
  serializeResponse(m: NormalizedMessage): unknown
}

// guardrails/types.ts — vocabulary aligned with industry convention
type Decision = 'allow' | 'redact' | 'block' | 'flag'

interface Detection {
  detector: string          // 'pii.email', 'secrets.aws_key', …
  entity_type: string       // 'EMAIL', 'CREDIT_CARD', 'AWS_ACCESS_KEY', …
  start: number
  end: number
  score: number             // 0..1
}

interface Verdict {
  decision: Decision
  detections: Detection[]   // the per-check breakdown
  transformed: boolean      // content was mutated (redaction applied)
}

interface Check {
  name: string
  stages: Array<'input' | 'stream' | 'output'>
  run(text: string): Detection[]
}
```

Redacted text uses entity-type placeholders: `[REDACTED_EMAIL]`,
`[REDACTED_CREDIT_CARD]` — the Bedrock/LLM Guard convention.

### Config (`warden.yaml`)

```yaml
providers:
  anthropic:
    api_key_env: ANTHROPIC_API_KEY
  openai_compat:
    base_url: https://api.openai.com/v1
    api_key_env: OPENAI_API_KEY

virtual_keys:
  - name: demo-app
    key_hash: "sha256:…"          # warden keys stored hashed
    rate_limit: { rpm: 60, burst: 10 }
    hmac: { enabled: false }

guardrails:
  pii:
    stages: [input, stream, output]
    entities: [EMAIL, PHONE, CREDIT_CARD, US_SSN, IBAN, IP_ADDRESS, MAC, URL, CRYPTO]
    action: redact                 # allow | redact | block | flag
  secrets:
    stages: [input, stream, output]
    action: block
  injection:
    stages: [input]
    action: flag
  blocklist:
    stages: [input, output]
    terms: []
    action: block
```

Per-guardrail, per-stage actions follow Bedrock's input/output action split,
extended with our `stream` stage.

## 5. Streaming filter (the centerpiece)

State-of-the-art buffer-and-scan (the pattern Guardrails AI and Bedrock
converged on), applied to SSE deltas:

1. Append each `text_delta` to a pending buffer.
2. Scan `held_tail + new_text` with all stream-stage checks on every tick.
3. Flush only text **provably past any partial match**: emit up to the last
   safe boundary (whitespace/sentence end), retain the tail. Hard cap on held
   length (default 256 chars) so pathological unbroken text still flows.
4. Detections spanning held text are replaced with placeholders before flush.
5. `message_end` scans and flushes the remainder.

**Restricted mid-stream actions** (you cannot unsend bytes): `redact` and
`flag` work per-delta; `block` after the first flush terminates the stream
with a structured SSE error event. This restriction is documented.

**Signature property — chunk-boundary invariance:** any re-chunking of the
same logical stream produces byte-identical redacted output. This is enforced
by a dedicated test suite and advertised in the README.

Latency trade-off (boundary hold-back) is documented honestly; the tail is
short, so the added latency is one boundary's worth of text, not
sentence-buffering on every token.

## 6. Honest scope statements (red-flag avoidance)

- **Regex tier is structured-PII + secrets only.** Cards, IBAN validated by
  checksum (Luhn etc.) — credible regex. NAME / ADDRESS / LOCATION need NER;
  v1 does not claim them. The `Check` interface is pluggable and the README
  documents the Presidio/NER upgrade path.
- **Single node, in-memory state.** Rate limits are not distributed-consistent;
  the `Store` interface is the Redis upgrade path. Stated, not hidden.
- **Prompt-injection heuristics are bypassable.** v1 ships pattern +
  Unicode/encoding-attack detection as a `flag`-by-default layer; classifier
  tier is roadmap.
- **HMAC signed requests are opt-in.** The market standard is Bearer virtual
  keys; HMAC adds integrity + replay protection for callers that want it.

## 7. Error handling

- **Fail closed.** Invalid config → refuse to start with precise messages.
  Guardrail engine failure → 500 block, never silent passthrough.
- **Auth:** 401; constant-time comparisons; HMAC timestamp window ±300s with
  in-memory replay cache.
- **Rate limit:** 429 + `RateLimit-*` and `Retry-After` headers.
- **Guardrail block:** 403 with structured body
  `{"error": {"type": "guardrail_blocked", "checks": [...]}}` (no unmasked
  content in the body). Flags surface via `X-Warden-Flagged: true` header.
- **Provider failures:** per-provider circuit breaker; 503 + `Retry-After`
  while open. Mid-stream provider errors (200 already sent) become structured
  SSE error events.
- **Logs/audit never contain unmasked content** — verdicts, entity types,
  spans, and metadata only.

## 8. Testing

- **Unit (vitest):** every detector against known-good/known-bad vectors
  (incl. Luhn/IBAN checksum cases); token-bucket math; HMAC verification;
  circuit-breaker state machine; SSE parsers against recorded fixtures of both
  provider dialects.
- **Invariance suite:** recorded streams re-split at random and adversarial
  boundaries (mid-email, mid-card-number) must produce byte-identical
  redacted output.
- **Integration:** mock provider server replays SSE fixtures; real
  `@anthropic-ai/sdk` and `openai` SDK clients pointed at warden complete
  streaming and non-streaming round-trips unchanged.
- **CI (GitHub Actions):** lint + typecheck + tests + Docker build on every
  PR; image to GHCR on tag.

## 9. v1 deliverables ("done" bar)

1. `kavumahamza/llm-warden` public repo, MIT, polished README with
   architecture diagram, design-notes section (why not a plugin kernel /
   split policy service), and honest-scope section.
2. Full test suite green in GitHub Actions, badges in README.
3. Docker image on GHCR; `docker compose up` + `examples/` curl scripts give a
   working demo with the mock provider (no real API key needed).
4. Profile README updated to feature llm-warden.

## 10. Roadmap (explicitly out of v1)

- Postgres audit log (+ row-level security), promptfoo red-team scorecard in
  CI, NER detector tier (Presidio opt-in), Redis `Store`, vault-based
  reversible anonymization, Cloud Run + Terraform deploy, injection
  classifier tier.
