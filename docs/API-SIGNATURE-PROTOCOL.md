# agent-mail HTTP API Signature Protocol v1

Replaces the plaintext `X-Api-Key` header with (a) an identity header and
(b) an HMAC-SHA256 request signature, so the **raw API key never crosses the
wire** and every request's method / path / timestamp / body are
integrity-protected. Complete switch — the old `X-Api-Key` header is no
longer read or accepted.

## Threat model (why)

Old scheme: `X-Api-Key: <raw_key>` on every request.

- Plaintext HTTP / LAN → MITM reads the raw key once → **permanent
  impersonation** (key is long-lived).
- No integrity check on the body → MITM can rewrite params/recipient and it
  is undetectable.
- Captured request can be replayed indefinitely.

New scheme: the raw key stays offline. The client derives
`sha256(raw_key)` (= the DB `api_keys.key_hash`) and uses it as the HMAC
secret — the exact analogue of `webhook_secret`. Only a one-time
signature + a timestamp go on the wire.

## Headers (all three required on every `/api/v1/*` request)

| Header            | Value                                                                  |
|-------------------|------------------------------------------------------------------------|
| `X-Api-Identity`  | Caller identity: the key's `domain_addr` (email) if address-scoped, else its `system_id`. ("address as URL") **May be omitted** — curl drops empty-valued headers, so a missing header is treated as `""` (empty-identity fallback). |
| `X-Api-Timestamp` | Current time, epoch **milliseconds**, decimal string.                  |
| `X-Api-Signature` | Lowercase hex of HMAC-SHA256 (see below).                              |

## Signing base string

Four LF (`\n`)-joined lines, **no trailing newline**:

```
<HTTP_METHOD>\n<path_and_query>\n<X-Api-Timestamp>\n<sha256_hex(body)>
```

- `<HTTP_METHOD>` — uppercase method, e.g. `POST`.
- `<path_and_query>` — the request target **exactly as sent**, including the
  query string, URL-encoded, with no scheme and no host
  (e.g. `/api/v1/whitelists?domain=alice%40x.com`).
- `<X-Api-Timestamp>` — the exact timestamp string from the header.
- `<sha256_hex(body)>` — lowercase hex SHA-256 of the raw request body bytes.
  Empty body → `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## Signature

```
sig = hex( HMAC-SHA256( key = sha256_hex(raw_api_key) bytes,
                        msg = base string bytes ) )
```

The HMAC key is `sha256_hex(raw_api_key)` — i.e. the DB `api_keys.key_hash`.
The client derives it offline from the raw key it holds; the server reads the
same value from the DB. **The raw key is never transmitted.**

## Server verification (`core/api/auth.rs::auth_layer`)

1. Require all three headers, else `401`.
2. Buffer the body (cap 30 MB, else `413`) so it can be hashed and forwarded.
3. Candidate keys = active, unexpired keys where
   `domain_addr = identity OR system_id = identity`.
   - **Empty-identity fallback:** if `X-Api-Identity` is `""`, the candidate
     set is *all* active, unexpired keys (still capped at 64 below). The
     signature then selects the one key that matches. This is a convenience
     for low-cardinality environments (e.g. the e2e suite) — production
     clients should send their real `domain_addr`/`system_id`.
4. For each candidate (capped at 64): compute the expected signature and
   **constant-time compare** with `X-Api-Signature`. On a match, also require
   `|now_ms - timestamp| <= 300000` (5-min freshness window). First pass wins
   → attach the `ApiKeyRecord` to request extensions and continue.
5. No match → `401`.

Downstream scope/domain guards (`require_scope`, `require_domain_match`, …)
are unchanged — they run against the attached `ApiKeyRecord` exactly as before.

## Quickstart (bash)

Self-contained sign-and-call helper (requires `openssl` + `sha256sum`):

```bash
API_KEY=***   # raw key; stays offline, only sha256(key) is used
HOST="http://localhost:8080"

# api <METHOD> <path_and_query> [json_body]
api() {
  local m="$1" p="$2" b="${3:-}" kh bh ts base sig
  kh=$(printf '%s' "$API_KEY" | sha256sum | awk '{print $1}')
  bh=$(printf '%s' "$b"     | sha256sum | awk '{print $1}')
  ts=$(date +%s%3N)
  base=$(printf '%s\n%s\n%s\n%s' "$m" "$p" "$ts" "$bh")
  sig=$(printf '%s' "$base" | openssl dgst -sha256 -hmac "$kh" | awk '{print $NF}')
  if [[ -n "$b" ]]; then
    curl -s -X "$m" "$HOST$p" -H "Content-Type: application/json" \
      -H "X-Api-Identity: " -H "X-Api-Timestamp: $ts" \
      -H "X-Api-Signature: $sig" -d "$b"
  else
    curl -s -X "$m" "$HOST$p" -H "X-Api-Identity: " \
      -H "X-Api-Timestamp: $ts" -H "X-Api-Signature: $sig"
  fi
}

api GET  /api/v1/whoami
api POST /api/v1/whitelists '{"direction":"to","domain_addr":"a@x.com","value":"@mx.test"}'
```

File upload: build the `multipart/form-data` body with a **fixed** boundary
into a temp file, sign that exact byte sequence, and send it with
`--data-binary @file` (curl's random `-F` boundary cannot be pre-hashed). The
e2e suite's `tests/lib/amail-sign.sh` (`amail_curl` / `amail_upload`) does
this; `tests/lib/amail_sign.py` is the equivalent for Python.

## Replay posture

The timestamp is bound into the signature, so a replayed request with a stale
timestamp is rejected. A replay that lands inside the 5-minute window is
possible (no nonce store) — the same posture as the webhook HMAC, which this
scheme references.

## Rollback

None (complete switch). To revert: restore the previous `auth_layer` and the
clients from git.

## Canonical test vector (cross-language parity)

Every implementation MUST reproduce this value: Rust (base + advanced +
e2e-tool), Python, TypeScript, and the browser frontend all assert it in
their unit tests.

```
raw_key     = "0123456789abcdef0123456789abcdef"
key_hash    = sha256(raw_key)
            = "3eb1bd439947eb762998e566ccc2e099c791118b2f40579cc4f7da2b5061b7f9"
method      = "POST"
path        = "/api/v1/whitelists?domain=alice%40x.com&value=%40mx-a.test"
timestamp   = "1756000000000"
body        = '{"direction":"to"}'
sha256(body)= "81df1509ce6b639e907305811eeb1b7cae15cc15a97e846ac5e7ff031e0e7ac9"
signature   = "cabf840e1d1a8dd9d6885762beae087f422dbd4d6d20c9ca404896120a45bcbd"

# empty-body (GET) case
method      = "GET"
path        = "/api/v1/whoami"
timestamp   = "1756000000000"
body        = ""
signature   = "1aac75c79bea9c60efb3280a384900ce649c346c3da5cc124361fc5070e55c74"
```
