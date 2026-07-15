# Appendix A — RAPP Reference Manual

Terse, normative-mirroring. The tutorial (chapters 1–8) teaches; this reference is what you keep
open while building. Section numbers cite `SPEC.md`. Requirements language (MUST / MUST NOT /
SHOULD / MAY) is RFC 2119 / RFC 8174.

## A.1 Canonicalization (§4)

- Values are **I-JSON** (RFC 7493), serialized by **RFC 8785 (JCS)**.
- Object keys sorted by UTF-16 code unit; no insignificant whitespace; shortest string escaping;
  non-ASCII emitted as raw UTF-8. Arrays keep order. Duplicate keys → error.
- Numbers: full RFC 8785 binary64 serialization; round-trip test MUST accept `0.1`. Reference
  profile restricts to exact integers/strings/bool/null/array/object.
- No Unicode NFC normalization for new content. No schema coercion.

## A.2 Hashing (§5)

- One hash: **SHA-256** (FIPS 180-4), lowercase, 64 hex.
- `H(space, v) = SHA-256(utf8(space) ‖ 0x0A ‖ canonical(v))`
- `Hb(space, octets) = SHA-256(utf8(space) ‖ 0x0A ‖ octets)`
- Spaces: `rapp/1:particle`, `rapp/1:wave`, `rapp/1:rappid`, `rapp/1:egg`, `rapp/1:egg-manifest`,
  `rapp/1:seal`.

## A.3 Identity — rappid (§6)

- Form: `rappid:@<owner>/<slug>:<64hex>`; `owner`/`slug` are `[a-z0-9]` with internal single
  hyphens (case-sensitive, RFC 7405). Tail is 64 lowercase hex.
- Mint **once**: keyless `tail = Hb("rapp/1:rappid", uuid4_octets)` (RFC 9562); keyed
  `tail = Hb("rapp/1:rappid", SPKI_DER)` (RFC 5280).
- MUST NOT: `sha256("<owner>/<slug>")` or any name-hash; MUST NOT recompute from mutable facts.
- Re-anchor (§6.3), verifiable via a signed frame in the chain, only for: (a) keyless→keyed,
  (b) key rotation (signed by old key), (c) pre-standard tail migrated once then deleted.

## A.4 The Frame (§7)

Exactly 11 keys: `spec, kind, stream_id, seq, utc, payload, payload_hash, frame_hash, prev,
prev_wave, sig`.

| field | rule |
|-------|------|
| `spec` | MUST be `"rapp/1"` |
| `kind` | `noun.verb`, lowercase labels |
| `stream_id` | rappid (biography) or `net:*` (swarm) |
| `seq` | uint53; genesis `0`, then `head.seq + 1` |
| `utc` | `YYYY-MM-DDTHH:MM:SS.mmmZ` (24 chars, ms, Z) |
| `payload` | I-JSON object |
| `payload_hash` | `H("rapp/1:particle", payload)` — the **particle** |
| `frame_hash` | `H("rapp/1:wave", frame∖{frame_hash,sig})` — the **wave** |
| `prev` | previous particle, or `null` at genesis |
| `prev_wave` | previous wave on `net:` past genesis; else `null` |
| `sig` | detached JWS (§10) or `null` |

**Build order:** particle first, then wave over the frame minus `{frame_hash, sig}`.

**Verify checklist (§7.5)** — returns the failing step:
1. shape & types (exactly 11 keys; `spec`; `kind`; `seq` uint53; `utc` fixed 24; `payload` object;
   hash fields well-formed). **1a.** stream binding: `stream_id == stream_of_record`.
2. particle: `payload_hash == H("rapp/1:particle", payload)`.
3. wave: `frame_hash == H("rapp/1:wave", frame∖{frame_hash,sig})`.
4. chain: genesis ⇒ `seq==0 ∧ prev==null`; else `seq==head.seq+1 ∧ prev==head.payload_hash ∧
   utc>=head.utc`.
5. wire: swarm past genesis ⇒ `prev_wave==head.frame_hash`; off-swarm ⇒ `prev_wave==null`.
6. signature: swarm frame MUST be signed; JWS verified per §10.

**Forks & re-genesis (§7.6):** forks resolved by stream authority, losing branch sealed.
Re-genesis: terminal `*.re-genesis` frame with `H("rapp/1:seal",…)` over old head → new genesis in
current form citing the sealed head → old frames retained under `legacy/` (sealed, never served).

## A.5 The Wire (§8)

- `POST /chat` with `{user_input, session_id?, conversation_history?}` →
  `{response, agent_logs, session_id}`. Only `user_input` is required.
- Errors typed: `422` malformed request, `401` needs token; frame rejection returns the failing
  verify step.
- Idempotency key on frame-appending ops; replay returns the same result (natural from
  content addressing).
- Streams: rappid = biography (`prev_wave` null, sig optional); `net:*` = swarm (`prev_wave`
  chains waves, sig REQUIRED).
- Tiers (local / cloud / studio) share the identical shape; only `RAPP_BRAINSTEM_URL` differs.

## A.6 The Egg (§9)

- Stored (uncompressed) ZIP; manifest + payload files. Variants: `organism`, `rapplication`,
  `session`, `invite`, `neighborhood`, `estate` — one spec, distinguished by field.
- Addresses: manifest `H("rapp/1:egg-manifest", manifest)`; egg `H("rapp/1:egg", archive)`
  **excluding** `sig` (sign after packing).
- `organism` MAY carry a constructor pin `{stream_id, seq, particle}` proving the parent frame it
  hatched from (verifiable by refetch+recompute).
- `invite` MUST be signed by the space's estate-owner succession.

## A.7 Signatures (§10)

- Detached **JWS** (RFC 7515) over the frame/egg integrity hash; unencoded-payload option
  (RFC 7797). Algorithms: EdDSA (RFC 8037) or ES256 (RFC 7518); deterministic ECDSA per RFC 6979.
- Keyed identity binds to the signing key via §6.2. Key discovery, rotation, and tombstone per
  §10; a keyed tail minted under a pre-standard (untagged) formula fails discovery and MUST be
  re-anchored (§6.3c).

## A.8 Conformance & Versioning (§11–§13)

- **Conformance classes (§11):** an implementation conforms when it produces and rejects exactly
  the `conformance.py` vectors (V1–V9) and honors the §7.5 checklist.
- **Versioning (§12):** one **living standard**; `rapp/1` never denotes two shapes. Change the one
  spec and migrate (no second `rapp/1`). Published content-addressed artifacts are immutable.
- **No legacy (§12 / Fed. Const. Art. III):** converge and delete; a legacy form encountered is a
  drift finding. Immutable chains converge by **re-genesis** (§12.1), old frames retained as sealed
  history (Amendment III-a).
- **Registry as root of trust (§13):** `rapp-map/ecosystem-spec.json`, owner-signed, anchored to an
  out-of-band `estate_owner` rappid fingerprint, `registry_seq`-monotonic. Owner succession is
  time-scoped (§13.2).

## A.9 The Reference Implementation

`rapp.py` (stdlib only) implements A.1–A.4: `canonical`, `H`/`Hb`, `mint_rappid`/`rappid_valid`,
`build_frame`/`verify_frame`. `conformance.py` runs V1–V9. `realcheck.py` runs the whole thing
against the live estate. Read `rapp.py` — it is ~140 lines and it is the spec made executable.

## A.10 Normative References

RFC 2119/8174 (requirements) · RFC 8785 (JCS) · RFC 8259/7493 (JSON/I-JSON) · FIPS 180-4
(SHA-256) · RFC 3986 (URI) · RFC 9562 (UUID) · RFC 5280 (X.509 SPKI) · RFC 7515/7797/8037/7518/6979
(JWS/signatures) · RFC 7405 (case-sensitive ABNF).
