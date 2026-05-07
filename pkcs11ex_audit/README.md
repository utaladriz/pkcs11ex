# pkcs11ex_audit

Append-only hash-chained audit log + RFC 3161 timestamp anchoring for [`pkcs11ex`](https://hex.pm/packages/pkcs11ex).

## What this does

- **Tamper-evident log** of arbitrary application events (typically: every JWS signature produced by `pkcs11ex`). Each entry's `content_hash` includes the previous entry's hash; walking the chain end-to-end and recomputing each hash detects any modification.
- **RFC 3161 timestamping** over chain heads. Anchoring binds the chain state to a TSA-attested time, closing the operator-replay/truncate gap that a bare hash chain doesn't cover.
- **Pluggable storage** via the `Pkcs11ex.Audit.Storage` behaviour. Ships an `InMemory` adapter (Agent-backed) for dev/tests; production deployments plug their own (Postgres, SQLite, append-only file with fsync, S3 + Object Lock, etc.).

## What this does NOT do

- **Encrypt entries**. Apps that need confidentiality encrypt the payload before calling `Pkcs11ex.Audit.append/3`.
- **Verify TSA timestamp tokens**. Anchoring stores the TST opaquely; auditors verify against the TSA's certificate chain in their own workflow.
- **Sign anything**. Audit log integrity is via hash chain + (optional) external timestamping. The "chain root signed by the platform key" pattern lives in application code if needed.

## Usage

```elixir
# In your supervision tree
children = [
  # Storage process — one per audit log
  {Pkcs11ex.Audit.Storage.InMemory, name: :signature_audit}
]

# Wherever you need an audit reference
audit = Pkcs11ex.Audit.new(Pkcs11ex.Audit.Storage.InMemory, :signature_audit)

# Plug it into Pkcs11ex.JWS.sign's audit hook
{:ok, jws} =
  Pkcs11ex.JWS.sign(payload,
    signer: {:platform, :signing},
    alg: :PS256,
    audit_to: audit,
    audit_extra: %{request_id: req_id}
  )

# Periodically anchor against a TSA
{:ok, _anchor_entry} =
  Pkcs11ex.Audit.anchor_head(audit, "http://timestamp.digicert.com")

# Verify chain integrity at any time
:ok = Pkcs11ex.Audit.verify(audit)
```

## Module map

| Module | Role |
|---|---|
| `Pkcs11ex.Audit` | Public API: `new/2`, `append/3`, `verify/1`, `head/1`, `at/2`, `anchor_head/3` |
| `Pkcs11ex.Audit.Entry` | Struct: `{seq, prev_hash, content_hash, payload, inserted_at}` |
| `Pkcs11ex.Audit.Storage` | Behaviour for storage adapters |
| `Pkcs11ex.Audit.Storage.InMemory` | Agent-backed in-memory adapter (not durable) |
| `Pkcs11ex.Audit.Anchor.RFC3161` | TSP request building + TSA HTTP transport |

## Relationship to `pkcs11ex`

This is a **sister library** — `pkcs11ex` doesn't pull this in by default. Apps that want signature audit trails add both as deps. The namespace is shared (`Pkcs11ex.Audit.*`) following the `Phoenix.PubSub` / `Plug.Crypto` convention for sub-libraries.

## License

Apache 2.0.
