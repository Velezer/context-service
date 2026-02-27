# context-service

HTTP + CLI context service with:

- Secure runtime context endpoint (`GET /context`)
- Context compression for token budgets (`POST /context/compress`)
- CRUD document management (`POST/GET/PUT/DELETE /documents/{id}`)
- Lightweight RAG retrieval endpoint (`POST /rag/query`)
- `context_cli` binary for GitHub Actions integration

## Run service

```bash
cargo run
```

Service binds to `0.0.0.0:8080`.

## Environment

```env
API_SECRET=your_shared_secret
RATE_LIMIT_SECS=1
CTX_APP_NAME=context-service
CTX_ENV=local
```

- `API_SECRET` enables HMAC auth on `GET /context`.
- `RATE_LIMIT_SECS` applies per-IP cooldown.
- `CTX_*` values are returned by `/context`.

## API usage

### `GET /context`

```bash
TS=$(date +%s)
SIG=$(printf "timestamp=%s" "$TS" | openssl dgst -sha256 -hmac "$API_SECRET" -binary | xxd -p -c 256)

curl -sS http://127.0.0.1:8080/context \
  -H "X-Timestamp: $TS" \
  -H "Authorization: $SIG" | jq
```

### `POST /context/compress`

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

### CRUD documents

```bash
curl -sS http://127.0.0.1:8080/documents -H 'Content-Type: application/json' -d '{
  "id":"doc-1",
  "title":"Action workflow",
  "content":"GitHub action uploads repo context and queries RAG"
}' | jq

curl -sS http://127.0.0.1:8080/documents/doc-1 | jq

curl -sS -X PUT http://127.0.0.1:8080/documents/doc-1 -H 'Content-Type: application/json' -d '{
  "title":"Action workflow v2",
  "content":"Updated workflow with tests and retrieval"
}' | jq

curl -sS -X DELETE http://127.0.0.1:8080/documents/doc-1 | jq
```

### RAG query

```bash
curl -sS http://127.0.0.1:8080/rag/query -H 'Content-Type: application/json' -d '{
  "query": "workflow retrieval tests",
  "top_k": 3
}' | jq
```

## CLI mode (`context_cli`)

Use the CLI to integrate in CI/CD and GitHub Actions.

```bash
cargo run --bin context_cli -- --server-url http://127.0.0.1:8080 compress \
  --context "Repo context" \
  --include README.md \
  --include src/main.rs \
  --max-tokens 180
```

CRUD + RAG from CLI:

```bash
cargo run --bin context_cli -- --server-url http://127.0.0.1:8080 create --id doc-1 --content "rust github action retrieval"
cargo run --bin context_cli -- --server-url http://127.0.0.1:8080 rag-query --query "github retrieval" --top-k 1
```

## GitHub Actions workflow

CI workflow runs formatting, clippy, and all tests (including e2e) on each push/PR.

## Test locally

```bash
cargo test
```
