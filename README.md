# context-service

A small HTTP service for exposing runtime context and compressing repository context into a token-budgeted summary for LLM workflows.

## What it does

- `GET /context`: Returns environment variables prefixed with `CTX_` as JSON.
- `POST /context/compress`: Accepts raw context and file contents, then returns a structured compressed context constrained by a token budget.

## Best-practice setup

### 1) Prerequisites

- Rust toolchain (matching `rust-toolchain.toml`)
- `cargo`
- Optional: `curl` for manual endpoint checks

### 2) Configure environment

Create a `.env` file in the project root:

```env
API_SECRET=your_shared_secret
RATE_LIMIT_SECS=1
CTX_APP_NAME=context-service
CTX_ENV=local
CTX_OWNER=platform-team
```

Notes:

- `API_SECRET` enables HMAC auth on `GET /context`.
- `RATE_LIMIT_SECS` sets per-IP minimum interval between requests.
- Any variable beginning with `CTX_` is exposed by `GET /context`.

### 3) Run the service

```bash
cargo run
```

Server binds to `0.0.0.0:8080`.

## Using `GET /context`

When `API_SECRET` is configured, requests must include:

- `X-Timestamp`: current unix timestamp in seconds
- `Authorization`: HMAC-SHA256 hex digest of `timestamp=<X-Timestamp>` using `API_SECRET`

### Generate auth headers (bash + openssl)

```bash
TS=$(date +%s)
SIG=$(printf "timestamp=%s" "$TS" | openssl dgst -sha256 -hmac "$API_SECRET" -binary | xxd -p -c 256)
```

### Call endpoint

```bash
curl -sS http://127.0.0.1:8080/context \
  -H "X-Timestamp: $TS" \
  -H "Authorization: $SIG" | jq
```

If `API_SECRET` is empty, signature checks are bypassed.

## Using `POST /context/compress`

### Request example

```bash
curl -sS http://127.0.0.1:8080/context/compress \
  -H 'Content-Type: application/json' \
  -d '{
    "context": "Monorepo service for API and worker runtime context.",
    "files": [
      {"path": "README.md", "content": "# Project\nUsage and architecture docs."},
      {"path": "src/main.rs", "content": "pub fn main() {}"}
    ],
    "max_tokens": 180
  }' | jq
```

### Response fields

- `summary`: High-level description of included material.
- `compressed_context`: Generated markdown summary/snippets.
- `estimated_tokens`: Approximate token count (`chars / 4`, rounded up).
- `truncated`: `true` if output was cut to fit token budget.


## Why you currently cannot open a pull request

If `git remote -v` prints nothing, this repository has no remote configured, so there is nowhere to push your branch and no platform (GitHub/GitLab) to open a PR against.

### Best-practice PR setup

1. Add your remote origin:

```bash
git remote add origin <your-repository-url>
```

2. Verify remotes:

```bash
git remote -v
```

3. Push your branch and set upstream:

```bash
git push -u origin $(git branch --show-current)
```

4. Open a pull request from your pushed branch (via your Git provider UI or CLI).

If your organization requires a fork model, add both `origin` (your fork) and `upstream` (main repo), then push to `origin` and open PR to `upstream`.

## Development workflow

### Run tests (includes e2e)

```bash
cargo test
```

### Run only end-to-end tests

```bash
cargo test --test e2e_compress --test e2e_usage --test e2e_auth_rejection
```

## Operational guidance

- Keep `API_SECRET` set in non-local environments.
- Use short `RATE_LIMIT_SECS` for interactive usage, higher for abuse-prone deployments.
- Avoid injecting sensitive values into `CTX_` variables unless clients are authorized to read them.
