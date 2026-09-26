"""registry_fixtures.py — synthetic §13 registry fixtures for tests and registry_conformance.py.

Stdlib only. The detached-JWS boundary is mocked with recorded test signatures, exactly
as test_registry_lifecycle.py does, so these fixtures prove the registry's authorization
orchestration without a cryptography library. `real_ed25519_signer` exercises the real
boundary when the optional `cryptography` import is present. Every name, key, and URL
here is synthetic.
"""
import base64
import contextlib
from unittest.mock import patch

import rapp as R
import rapp_registry as REG

SOURCE = "https://registry.example.test/rapp-registry.json"
T0 = "2026-07-01T00:00:00.000Z"
LATE = "2099-12-31T23:59:59.999Z"
# Names git's ref-name rules (`git check-ref-format`) refuse, one per rule the reference implements (§3).
BAD_TAG_NAMES = ("refs/tags/a..b", "refs/tags/.hidden", "refs/tags/x.lock", "refs/tags/a.", "refs/tags/a/",
                 "refs/tags/a//b", "refs/tags/a@{1}", "refs/tags/a b", "refs/tags/a\nb", "refs/tags/a\x7fb",
                 "refs/tags/a~b", "refs/tags/a^b", "refs/tags/a:b", "refs/tags/a?b", "refs/tags/a*b",
                 "refs/tags/a[b", "refs/tags/a\\b")


class MockEstate:
    """A synthetic estate whose keys sign by recorded token, never by cryptography."""

    def __init__(self, names=("owner", "worker", "successor", "outsider")):
        self.der, self.keys, self.signatures = {}, {}, {}
        for name in names:
            self.add_key(name)

    def add_key(self, name):
        der = ("synthetic-public-key-" + name).encode()
        kid = R.mint_rappid("test", name, spki_der=der)
        self.der[kid] = der
        self.keys[name] = kid
        return kid

    def sign(self, value, kid):
        token = "test-signature-" + str(len(self.signatures))
        self.signatures[token] = (R.canonical(value), kid, self.der[kid])
        return token

    def verify(self, value, sig, der, expected_kid=None):
        expected = self.signatures.get(sig)
        actual = (R.canonical(value), expected_kid, der)
        return (True, "ok") if expected == actual else (False, "invalid test signature")

    def spki(self, name, deprecated=False):
        kid = self.keys[name]
        return {"type": "spki", "rappid": kid, "deprecated": deprecated,
                "spki_der_b64": base64.b64encode(self.der[kid]).decode("ascii")}

    def base_entries(self, owner="owner"):
        return [{"type": "estate_owner", "rappid": self.keys[owner]}] + [
            self.spki(name) for name in self.keys
        ]

    def declare(self, entry, signer="owner"):
        """Sign one declared entry (§13.4) over canonical(entry \\ {sig})."""
        value = {k: v for k, v in entry.items() if k != "sig"}
        value["sig"] = self.sign(value, self.keys[signer])
        return value

    def document(self, entries, owner="owner", seq=2, source=SOURCE, extra=None, signed=True):
        value = {"schema": "rapp/1-registry", "registry_seq": seq,
                 "canonical_source": source, "entries": entries}
        value.update(extra or {})
        value["sig"] = self.sign(value, self.keys[owner]) if signed else None
        return value

    @contextlib.contextmanager
    def mocked(self):
        with patch.object(R, "verify_detached_jws", side_effect=self.verify):
            yield

    def load(self, document, owner="owner", **kwargs):
        kwargs.setdefault("tombstone_issued_at", lambda entry_hash: T0)
        if "first_seen" not in kwargs and "verification_utc" not in kwargs:
            # Fixture default: every declared entry first seen late enough for the 300 s rule.
            kwargs["verification_utc"] = LATE
        with self.mocked():
            return REG.load_document(document, trust_anchor=self.keys[owner], **kwargs)

    def reanchor(self, old, new, signer, case="rotation", utc=T0):
        value = {"type": "re-anchor", "old_rappid": self.keys[old],
                 "new_rappid": self.keys[new], "case": case, "utc": utc}
        if case == "rotation":
            value["old_key_sig"] = self.sign(value, self.keys[old])
        value["sig"] = self.sign(value, self.keys[signer])
        return value

    def grail_kernel(self, scope="https://releases.example.test/scope/lts",
                     declared="owner", activated=T0, predecessor=None,
                     sha256="a" * 64, signer=None):
        entry = {
            "type": "grail-kernel", "release_scope": scope,
            "grail_id": "grail:" + R.Hb("rapp/1:grail", ("kernel bytes " + scope).encode()),
            "repository": "https://git.example.test/estate/kernel",
            "immutable_ref": "refs/tags/kernel-v1", "object_format": "sha1",
            "commit": "1" * 40, "path": "kernel/brainstem.py", "mode": "100644",
            "blob": "2" * 40, "sha256": sha256, "size_bytes": 1024,
            "activated_utc": activated, "predecessor": predecessor,
            "declared_by": self.keys[declared],
        }
        return self.declare(entry, signer or declared)


def real_ed25519_signer():
    """(spki_der, sign) for a fresh Ed25519 key, or None without the optional `cryptography`."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        return None
    private_key = ed25519.Ed25519PrivateKey.generate()
    spki_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def b64url(octets):
        return base64.urlsafe_b64encode(octets).rstrip(b"=").decode("ascii")

    def sign(value, kid):
        header = {"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": kid}
        protected = b64url(R.canonical(header).encode("utf-8"))
        signing_input = (protected + "." + R.canonical(value)).encode("utf-8")
        return protected + ".." + b64url(private_key.sign(signing_input))

    return spki_der, sign
