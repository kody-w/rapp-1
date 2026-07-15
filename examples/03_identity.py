"""03 — Identity. Mint a rappid the one lawful way, and see why a name-hash is forbidden.

A rappid is `rappid:@<owner>/<slug>:<64hex>`. The 64-hex tail is minted ONCE from
entropy (keyless) or from a public key (keyed) — it is NEVER sha256("owner/slug").
A name-hash collides the moment two things share a name, which is the whole disease
RAPP §6 exists to end. Run: python3 examples/03_identity.py
"""
import sys, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rapp as R

# Keyless: tail = Hb("rapp/1:rappid", uuid4_octets) — a stable, opaque join key.
keyless = R.mint_rappid("kody", "twin")
print("keyless :", keyless, "  valid:", R.rappid_valid(keyless))

# Keyed: tail = Hb("rapp/1:rappid", SPKI_DER) — verifiable against the public key.
spki = b"\x30\x2a...your-DER-SubjectPublicKeyInfo-here..."
keyed = R.mint_rappid("kody", "twin", spki_der=spki)
print("keyed   :", keyed)
print("keyed is deterministic (mint-once):", R.mint_rappid("kody", "twin", spki) == keyed)

# The forbidden mint — DO NOT DO THIS. Shown so you can recognise it in the wild.
name_hash = hashlib.sha256(b"kody/twin").hexdigest()
print("\nFORBIDDEN name-hash tail:", name_hash)
print("  → collides for every actor that ever names something 'kody/twin'.")
print("  → RAPP's mint tail differs from it:", keyless.rsplit(':', 1)[1] != name_hash)
