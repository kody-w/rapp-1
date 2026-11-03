# RAPP Succession
## Who inherits a device-local chain

**Protocol identifier:** `rapp-succession/1`
**Status:** Proposed subordinate RAPP/1 profile; not a signed registry adoption
**Parent:** [`rapp/1`](../../../SPEC.md)
**Depends on:** `rapp/1` only
**Schema:** [`schema.json`](schema.json)

The chain is the asset. This profile records whose device-local Brainstem it
is and who may inherit it, without putting a private key in the chain or the
AI. It specifies cryptographic authority, not probate, legal ownership,
proof of death, delivery of notifications, or recovery of lost private keys.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** have
their RAPP/1 section 2 meanings.

## 1. Substrate and scope

Payloads **MUST** be canonical RAPP/1 I-JSON in the unchanged eleven-key
`spec:"rapp/1"` frame. This profile adds no endpoint, envelope member, hash
domain, registry-entry type, or wire form. All ordinary frame, hash, size,
depth, stream, sequence, and non-regressing timestamp checks still apply.
The three exact kinds below belong to the `memory` family and use a
device-local memory stream. A kind's prefix is not a family declaration;
an adopting estate registers these ordinary kinds under RAPP/1 section 13.
This proposal is not evidence that such adoption has occurred.

These frames **MAY** interleave with `rapp-layer/1` frames in one device
chain. Each reader ignores the other profile's payload semantics, not chain
links. A shape gate is not proof of life. A succession handoff is not a
shape gate. Readers **MUST NOT** count unrelated frames as owner activity.
Present signatures are never treated as verified without a real verifier.

All three succession kinds **MUST** have `sig != null`: a section 10
Ed25519 detached, unencoded JWS (`alg:"EdDSA"`), with `kid` equal to the
signer's keyed rappid. Verification signs `canonical(frame \ {sig})`,
including `frame_hash`. The protected header has exactly `alg,b64,crit,kid`;
`b64:false`, `crit:["b64"]`, and canonical unpadded base64url still apply.

## 2. Naming an owner and successor

`succession.name` has exactly this payload:

```json
{
  "schema": "rapp-succession/1",
  "owner": {"rappid": "<keyed rappid>", "spki_der_b64": "<base64 DER SPKI>"},
  "successor": {
    "name": "<plain name, 1..120 characters>",
    "rappid": "<keyed rappid>",
    "spki_der_b64": "<base64 DER SPKI>"
  },
  "window": {"silence_days": 1, "confirm_days": 0}
}
```

Every object is closed: extra or missing members **MUST** be refused.
`name` is an NFC plain string of 1..120 Unicode characters, never markup
to execute. `silence_days` is an integer 1..3650; `confirm_days` is an
integer 0..365. Booleans are not integers. A day is exactly 86,400 seconds
in UTC, not a local calendar day.

Both SPKIs **MUST** be Ed25519 DER SubjectPublicKeyInfo, in canonical padded
standard base64. Both rappids **MUST** satisfy section 6.1 and the section 10
tail check `Hb("rapp/1:rappid", SPKI_DER) == tail`. A name, slug, URL, or
unchecked public key is not authority.

The **first** valid `succession.name` establishes the chain's owner key.
It **MUST** be signed by its `owner`, verified with `owner.spki_der_b64`.
This is the **device-local root**: there is no section 13 registry on the
device. Subsequent nominations **MUST** carry the current owner's keyed
identity and key and be signed by that owner. The nomination replaces the
pending successor and both windows. Anyone else's nomination is refused.
After a handoff, "current owner" means the heir, not the genesis identity.

This local public-key discovery rule deliberately substitutes for estate
registry discovery; it does not claim to satisfy section 10's registry
discovery for an exported estate-authoritative artifact. A consumer **MUST**
protect/pin its accepted root and head out of band. An attacker able to
replace the entire unpinned local history can forge another local root.
The profile does not detect rollback or competing copies by itself.
Timestamps are signed claims, not an independent clock or proof of death.
A host enforcing real elapsed inactivity **MUST** also protect its clock
and append policy; a successor's future-dated frame alone proves only the
declared timestamp inequalities, not that wall-clock time has elapsed.

## 3. Signs of life

`succession.pulse` has exactly this payload:

```json
{"schema":"rapp-succession/1","head":"<frame_hash of the previous frame>"}
```

It **MUST** follow a valid nomination and be signed by the current owner.
`head` **MUST** identify the immediately previous frame, even when that
frame belongs to another profile. It is a wave hash, not the envelope's
particle-valued `prev`.

Any owner-signed frame **of this profile** counts as life.
`last_owner_utc` is the UTC of the newest such frame in verified chain
order. A valid nomination or pulse resets both deadlines:

`silence_deadline = last_owner_utc + silence_days`

`confirm_deadline = silence_deadline + confirm_days`

At the first deadline the owner is silent; at the second, a silence handoff
is open. Zero confirmation days makes both deadlines equal. Crossing a
deadline does **not** append a frame or transfer ownership. A fresh owner
pulse or nomination closes the old window, even after it was open.

## 4. Handoff and key lifecycle

`succession.handoff` has exactly this payload:

```json
{
  "schema": "rapp-succession/1",
  "from_head": "<frame_hash of the previous frame>",
  "reason": "<owner or silence>",
  "at": "<RAPP UTC timestamp>"
}
```

A handoff without a prior nomination **MUST** be refused. `from_head`
**MUST** be the immediately previous frame's wave hash, including when
that frame is a shape frame.

- `reason:"owner"` **MUST** be signed by the current owner and is valid
  any time. `at` is a calendar-valid RAPP timestamp but imposes no silence
  window; the frame's UTC is the authority transition time.
- `reason:"silence"` **MUST** be signed by the **current successor** and
  requires `at >= confirm_deadline` **and** `frame.utc >= at`.
  Otherwise it is refused with `handoff before the window`.

After a valid handoff the successor becomes the owner for every later
frame of this profile. The outgoing key is superseded: later signatures by
it at `utc >= handoff.utc` **MUST** be refused, mirroring section 10's
forward key lifecycle. The handoff itself remains valid, including when
signed by the outgoing owner. Verification walks history in order and
does not retroactively revoke the already-verified prefix.

The nomination is consumed: there is no pending successor or deadline
until the new owner signs a new `succession.name`. The handoff UTC is the
new tenure's life baseline; subsequent owner activity updates it. A pulse
by the new owner is permitted before the next nomination, but it does not
recreate a consumed nomination. A repeated handoff without a new nominee
is refused. `inherited` describes this consumed-nomination state, not a
permanent priority over future silence statuses.

The chain's `stream_id` **MUST NOT** change at handoff. The heir continues
the same asset; its stream identity need not equal its owner's rappid.
Moving the chain into the heir's estate uses ordinary RAPP/1 section 12.1
owner-authorized re-genesis, outside this profile. No new migration
mechanism, legal contract, or private-key escrow is implied.

## 5. Reader, signer, and conformance

[`rapp_succession.py`](../../../rapp_succession.py) exposes:

`validate_chain(frames)` verifies the whole chain in order and every
succession signature using `rapp.verify_detached_jws`. It raises
`ValueError` with plain words on a refusal; it never repairs frames.
Unknown `succession.*` kinds are refused. Unrelated payload semantics are
ignored; signed unrelated frames still require a discoverable public key.
The reference resolves those keys only from nominations encountered in
this chain; it does not invent an estate registry.

`state(frames, now_utc)` verifies before returning exactly:

```json
{
  "owner": "<rappid or null>",
  "successor": {"name": "<plain name>", "rappid": "<keyed rappid>"},
  "last_owner_utc": "<UTC or null>",
  "silence_deadline": "<UTC or null>",
  "confirm_deadline": "<UTC or null>",
  "status": "<unnamed, owned, silent, handoff-open, or inherited>"
}
```

`successor` is null when absent. `unnamed` means no nomination has ever
established an owner; `owned` means before silence; `silent` means at or
after silence but before confirmation; `handoff-open` means at or after
confirmation with no handoff yet. `inherited` means a completed handoff
with no fresh nomination. `now_utc` is an observation clock, not a filter:
all supplied frames are verified/projected. A historical view needs the
appropriate verified chain prefix. A deadline past year 9999 is explicitly
refused rather than wrapped or silently omitted; year 0000 is supported.

`sign_frame(kind, stream_id, seq, utc, payload, prev, private_key_pem)`
builds the ordinary frame and its real Ed25519 detached JWS. `prev` is the
previous **payload_hash**; the payload's `head`/`from_head` is separately
the previous **frame_hash**. The caller manages key custody.

**Signer identity limitation:** a PEM contains a key, not its rappid's
owner/slug. A nomination supplies the signing identity in `owner`; pulses
and handoffs intentionally do not. For those, pass
`SigningKey(pem_bytes, signer_rappid)`, a bytes-compatible ephemeral PEM
wrapper carrying only the additional public identity. There is no global
identity cache, inferred label, private-key file, or hidden signer state.

Only Python stdlib modules are imported by the reader itself; section 10
verification and signing require `cryptography`, already used by the base
reference. No other dependency is introduced. From an environment lacking
it: `python3 -m venv .venv`, `. .venv/bin/activate`, then
`python3 -m pip install cryptography`.

`python3 succession_conformance.py protocols/examples/succession-lifecycle.json`
checks registration hashes, anchor input registration, real fixture
signatures, and adversarial unit vectors. The fixture has five real frames:
genesis, nomination, pulse, silence handoff, heir nomination. All keys were
generated for authoring; only public SPKIs and signatures are retained.
An early handoff is a refused negative vector, never part of that chain.
Schema checks structure only; signatures, tail binding, deadlines,
authorization, and links require the reader.
The anchor generator validates current committed profile inputs, but
replays an already accepted revision against that revision's accepted
profile snapshot. Adding this proposal does not rewrite the protected
anchor; its profile metadata is available to the next authorized revision.

## 6. Who paid

- **Google Inactive Account Manager** supplies the silence-then-confirmation
  model: [Google's explanation](https://support.google.com/accounts/answer/3036546).
  This profile does not claim to duplicate Google's exact timing, reminders,
  or account recovery behavior.
- **PGP key-transition statements** teach that the old key should sign the
  statement naming the next one:
  [Debian's key-transition guidance](https://wiki.debian.org/Keysigning).
  These are lessons in authenticated continuity, not an OpenPGP wire form.
- **Bitcoin inheritance losses** teach that key custody, not a written
  contract alone, determines whether an heir can actually use a key:
  [Bitcoin's wallet-backup guidance](https://bitcoin.org/en/secure-your-wallet).
  No numerical loss estimate or automatic legal succession is asserted.
- **RAPP/1 sections 10 and 13** supply detached JWS, key fingerprints,
  lifecycle boundaries, and the distinction between local bootstrap trust
  and an estate's authenticated registry. Section 12.1 already supplies
  re-genesis. This profile borrows those lessons without altering the core.
