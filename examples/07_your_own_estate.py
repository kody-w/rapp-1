"""07 — Your own estate. Extending RAPP without touching rapp-1.

RAPP grows by registration (Constitution Art. 4). A vendor, a team, or one laptop
becomes an *estate* by publishing its own §13 registry: that document — not this
repository — binds the estate's kinds to families, admits its egg variants and
error codes, discovers its signers' keys, and retires keys by tombstone. This
program writes such a registry for a fictional estate ("acme"), then checks real
frames against it with the reference. Run: python3 examples/07_your_own_estate.py

Nothing here is signed. An unsigned registry is a DRAFT; the reference says so and
never calls it verified. The stand-in SPKI bytes are not a key.
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rapp as R
import rapp_registry as REG

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def show(label, ok, why=""):
    print(f"  [{'OK' if ok else '--'}] {label}" + (f" — {why}" if why else ""))

# ── 1. Identities. Keyed rappids hash an SPKI; these bytes stand in for one. ──
OWNER_SPKI = b"stand-in SPKI bytes: not a key, only its fingerprint matters here"
OLD_SPKI = b"an earlier owner key, since rotated"
owner = R.mint_rappid("acme", "estate-owner", spki_der=OWNER_SPKI)
old_owner = R.mint_rappid("acme", "estate-owner", spki_der=OLD_SPKI)
factory = R.mint_rappid("acme", "widget-factory")          # keyless organism
print("estate owner:", owner)

# ── 2. Pin the protocol THROUGH THE ANCHOR, never by a hand-typed hash. ──
orient = json.load(open(os.path.join(ROOT, "anchor", "orient.json")))
rapp1_pin = {"type": "protocol", "name": "rapp/1", "deprecated": False,
             "spec_repo": "https://github.com/kody-w/rapp-1", "spec_path": "SPEC.md",
             "spec_hash": orient["spec"]["normative_sha256"]}
print("rapp/1 pinned at", orient["spec"]["revision"], rapp1_pin["spec_hash"][:16], "…")

# ── 3. The estate's registry entries — every one an exact §13.3 shape. ──
import base64
entries = [
    {"type": "estate_owner", "rappid": owner},
    {"type": "spki", "rappid": owner, "deprecated": False,
     "spki_der_b64": base64.b64encode(OWNER_SPKI).decode("ascii")},
    {"type": "spki", "rappid": old_owner, "deprecated": True,
     "spki_der_b64": base64.b64encode(OLD_SPKI).decode("ascii")},
    {"type": "re-anchor", "old_rappid": old_owner, "new_rappid": owner, "case": "rotation",
     "utc": "2026-06-01T00:00:00.000Z", "sig": "<owner-signed>", "old_key_sig": "<old-key-signed>"},
    rapp1_pin,
    # The vendor's own vocabulary. The first label is the vendor's; the family is a binding, not a prefix.
    {"type": "kind", "kind": "acme.widget-made", "family": "body", "deprecated": False},
    {"type": "kind", "kind": "acme.turn", "family": "memory", "deprecated": False},
    {"type": "kind", "kind": "acme.broadcast", "family": "swarm", "deprecated": False},
    {"type": "egg-variant", "variant": "acme-bundle", "deprecated": False},
    {"type": "error-code", "code": "acme-refused"},
    # A signer that was compromised on July 1st.
    {"type": "tombstone", "rappid": old_owner, "revoked_utc": "2026-07-01T00:00:00.000Z", "sig": "<owner-signed>"},
]
reg = REG.Registry(entries)
print(f"\nregistry loaded: {len(reg.kinds)} kinds, {len(reg.egg_variants)} variants, "
      f"{len(reg.error_codes)} error codes, owner {reg.estate_owner[:30]}…")

# ── 4. Frames check against THIS registry, not against rapp-1. ──
print("\nframe binding (§7.2 family ↔ §6.1.1 stream form):")
body = R.build_frame("acme.widget-made", factory, 0, "2026-08-01T00:00:00.000Z", {"serial": 1}, None)
ok, step, why = R.verify_frame(body, head=None, stream_id_of_record=factory)
bound, breason = reg.check_frame_binding(body)
show("body kind on a body-stream: reference verify + registry binding", ok and bound, breason)
assert ok and bound

mem = R.build_frame("acme.widget-made", factory + ":laptop", 0, "2026-08-01T00:00:00.000Z", {}, None)
bound, breason = reg.check_frame_binding(mem)
show("body kind on a memory-stream is refused", not bound, breason); assert not bound

stranger = R.build_frame("foo.bar", factory, 0, "2026-08-01T00:00:00.000Z", {}, None)
ok, _, _ = R.verify_frame(stranger, head=None, stream_id_of_record=factory)
bound, breason = reg.check_frame_binding(stranger)
show("grammatical but unregistered kind: reference passes shape, registry refuses", ok and not bound, breason)
assert ok and not bound

# ── 5. Time-scoped authority (§10, §13.2). ──
print("\nsigner and owner, scoped in time:")
ok, why = reg.signer_acceptable(old_owner, "2026-05-01T00:00:00.000Z")
show("old key before rotation: acceptable", ok, why); assert ok
ok, why = reg.signer_acceptable(old_owner, "2026-06-15T00:00:00.000Z")
show("old key after rotation: refused", not ok, why); assert not ok
ok, why = reg.signer_acceptable(owner, "2026-08-01T00:00:00.000Z")
show("current key: acceptable", ok, why); assert ok
show("owner in effect 2026-05: the old key", reg.owner_at("2026-05-01T00:00:00.000Z") == old_owner)
show("owner in effect 2026-08: the new key", reg.owner_at("2026-08-01T00:00:00.000Z") == owner)

# ── 6. The document envelope (§13.1): draft is not authority; rollback is refused. ──
print("\ndocument envelope:")
doc = {"schema": "rapp/1-registry", "registry_seq": 7, "entries": entries, "sig": None}
status, _, why = REG.load_document(doc, entries_member="entries")
show("unsigned registry is refused by default", status == "refused", why); assert status == "refused"
status, _, why = REG.load_document(doc, entries_member="entries", allow_unsigned=True)
show("with allow_unsigned it is a DRAFT, never verified", status == "draft", why); assert status == "draft"
status, _, why = REG.load_document(doc, entries_member="entries", allow_unsigned=True, persisted_seq=9)
show("registry_seq below the persisted one is a rollback", status == "refused", why); assert status == "refused"

# ── 7. Refusals are whole: one malformed entry refuses the registry. ──
print("\nrefusals (never repaired, never partial):")
for label, bad in [
    ("kind registered twice", entries + [{"type": "kind", "kind": "acme.turn", "family": "body", "deprecated": False}]),
    ("kind with a stray member", entries + [{"type": "kind", "kind": "acme.x", "family": "body", "deprecated": False, "note": "no"}]),
    ("family outside memory/swarm/body", entries + [{"type": "kind", "kind": "acme.y", "family": "vendor", "deprecated": False}]),
    ("rotation without old_key_sig", entries + [{"type": "re-anchor", "old_rappid": owner, "new_rappid": old_owner, "case": "rotation", "utc": "2026-09-01T00:00:00.000Z", "sig": "s"}]),
    ("a second protocol claiming the rapp/1 namespace", entries + [{"type": "protocol", "name": "rapp/1-plus", "spec_repo": "https://example.invalid/x", "spec_path": "S.md", "spec_hash": "0"*64, "deprecated": False}]),
    ("spki that does not hash to its rappid tail", [entries[0], {"type": "spki", "rappid": owner, "deprecated": False, "spki_der_b64": base64.b64encode(b"wrong").decode()}]),
    ("two estate owners", entries + [{"type": "estate_owner", "rappid": factory}]),
]:
    try:
        REG.Registry(bad); show(label, False, "was accepted"); raise SystemExit(1)
    except REG.RegistryError as e:
        show(label, True, str(e)[:70])

print("\nThis estate needed nothing from rapp-1 but the pin. That is the extension model.")
