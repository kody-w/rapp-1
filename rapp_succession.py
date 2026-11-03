#!/usr/bin/env python3
"""Device-local succession over unchanged RAPP/1 frames.

The reader uses stdlib helpers and rapp.verify_detached_jws; real signature
verification and the opt-in signing helper require cryptography.
"""

from __future__ import annotations

import base64
import binascii
import copy
from datetime import datetime
from pathlib import Path
from typing import Sequence

import rapp as R
from rapp_profile import bounded_int, canonical_object, exact_keys, hex64, require, text

PROFILE = "rapp-succession/1"
SPEC_PATH = "protocols/rapp-succession/1/SPEC.md"
KINDS = frozenset({"succession.name", "succession.pulse", "succession.handoff"})
DAY_MS = 86_400_000


def _instant(value: object, where: str) -> int:
    require(isinstance(value, str) and R.utc_valid(value),
            f"{where}: expected a valid RAPP UTC timestamp")
    # datetime has no year zero; a Gregorian 400-year cycle preserves its dates.
    year = int(value[:4])
    parsed = datetime.strptime(("0400" + value[4:]) if year == 0 else value,
                               "%Y-%m-%dT%H:%M:%S.%fZ")
    ordinal = parsed.toordinal() - (146_097 if year == 0 else 0)
    return (ordinal * DAY_MS + parsed.hour * 3_600_000
            + parsed.minute * 60_000 + parsed.second * 1000
            + parsed.microsecond // 1000)


def _stamp(value: int) -> str:
    ordinal, clock = divmod(value, DAY_MS)
    require(ordinal <= datetime.max.toordinal(),
            "succession window runs past year 9999")
    date = datetime.fromordinal(ordinal + (146_097 if ordinal < 1 else 0))
    year = 0 if ordinal < 1 else date.year
    hours, clock = divmod(clock, 3_600_000)
    minutes, clock = divmod(clock, 60_000)
    seconds, millis = divmod(clock, 1000)
    return (f"{year:04d}-{date.month:02d}-{date.day:02d}T"
            f"{hours:02d}:{minutes:02d}:{seconds:02d}.{millis:03d}Z")


def _key(value: object, where: str, *, named: bool = False) -> dict:
    keys = {"rappid", "spki_der_b64"} | ({"name"} if named else set())
    exact_keys(value, keys, where)
    if named:
        text(value["name"], f"{where}.name", maximum=120)
    rid = value["rappid"]
    require(isinstance(rid, str) and R.rappid_valid(rid),
            f"{where}.rappid: expected a keyed rappid")
    encoded = value["spki_der_b64"]
    require(isinstance(encoded, str), f"{where}: public key must be base64 DER SPKI")
    try:
        der = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError(f"{where}: public key must be base64 DER SPKI") from error
    require(base64.b64encode(der).decode("ascii") == encoded,
            f"{where}: public key must use canonical padded base64")
    require(len(der) == 44 and R._spki_ok(der),
            f"{where}: public key must be an Ed25519 DER SPKI")
    require(R.Hb("rapp/1:rappid", der) == R.rappid_parts(rid)["hash"],
            f"{where}: public key does not match the rappid tail")
    return copy.deepcopy(value)


def validate_payload(kind: str, payload: dict) -> dict:
    canonical_object(payload, "succession payload")
    require(kind in KINDS, "unknown succession kind")
    keys = {
        "succession.name": {"schema", "owner", "successor", "window"},
        "succession.pulse": {"schema", "head"},
        "succession.handoff": {"schema", "from_head", "reason", "at"},
    }[kind]
    exact_keys(payload, keys, kind)
    require(payload["schema"] == PROFILE, "succession payload has the wrong schema")
    if kind == "succession.name":
        _key(payload["owner"], "owner")
        _key(payload["successor"], "successor", named=True)
        window = exact_keys(payload["window"], {"silence_days", "confirm_days"}, "window")
        bounded_int(window["silence_days"], "window.silence_days", 1, 3650)
        bounded_int(window["confirm_days"], "window.confirm_days", 0, 365)
    elif kind == "succession.pulse":
        hex64(payload["head"], "pulse.head")
    else:
        hex64(payload["from_head"], "handoff.from_head")
        require(payload["reason"] in ("owner", "silence"),
                "handoff reason must be owner or silence")
        _instant(payload["at"], "handoff.at")
    return copy.deepcopy(payload)


class SuccessionChain:
    """Verified ownership projection; other kinds never change succession state."""

    def __init__(self, frames: Sequence[dict]):
        require(bool(frames), "chain: genesis is required")
        self.frames = copy.deepcopy(list(frames))
        self.owner = None
        self.successor = None
        self.window = None
        self.last_owner_utc = None
        self.inherited = False
        self._keys = {}
        self._superseded = set()
        head = None
        stream_id = None
        for position, frame in enumerate(self.frames):
            canonical_object(frame, f"frame {position}")
            kind = frame.get("kind")
            require(isinstance(kind, str), f"frame {position}: kind must be a string")
            is_succession = kind.startswith("succession.")
            if is_succession:
                require(kind in KINDS, "unknown succession kind")
                payload = validate_payload(kind, frame.get("payload"))
                require(frame.get("sig") is not None, "succession frame must be signed")
                if kind != "succession.name":
                    require(self.owner is not None, "no prior succession name")
                if kind == "succession.name":
                    for key in (payload["owner"], payload["successor"]):
                        self._keys[key["rappid"]] = base64.b64decode(key["spki_der_b64"])
            if position == 0:
                stream_id = frame.get("stream_id")
                require(isinstance(stream_id, str)
                        and R.stream_form(stream_id) == "memory-stream",
                        "succession chain must use a device-local memory stream")
            ok, step, why = R.verify_frame(
                frame, head=head, stream_id_of_record=stream_id,
                signature_verifier=self.verify_signature)
            require(ok, f"frame {position}: RAPP refusal at step {step}: {why}")
            if is_succession:
                header, _, _ = R.parse_detached_jws(frame["sig"])
                signer = header["kid"]
                require(header["alg"] == "EdDSA", "succession signatures must use Ed25519")
                require(signer not in self._superseded, "signer is a superseded owner")
                if kind == "succession.name":
                    owner = payload["owner"]
                    require(signer == (self.owner["rappid"] if self.owner else owner["rappid"])
                            and signer == owner["rappid"],
                            "succession name must be signed by the current owner")
                    self.owner = owner
                    self.successor = payload["successor"]
                    self.window = payload["window"]
                    self.last_owner_utc = frame["utc"]
                    self.inherited = False
                else:
                    field = "head" if kind == "succession.pulse" else "from_head"
                    require(head is not None and payload[field] == head["frame_hash"],
                            f"{kind}: {field} must name the previous frame hash")
                    if kind == "succession.pulse":
                        require(signer == self.owner["rappid"],
                                "succession pulse must be signed by the current owner")
                        self.last_owner_utc = frame["utc"]
                    else:
                        require(self.successor is not None, "no current successor; name one first")
                        if payload["reason"] == "owner":
                            require(signer == self.owner["rappid"],
                                    "owner handoff must be signed by the current owner")
                        else:
                            require(signer == self.successor["rappid"],
                                    "silence handoff must be signed by the current successor")
                            require(_instant(payload["at"], "handoff.at") >= self._deadlines()[1]
                                    and frame["utc"] >= payload["at"],
                                    "handoff before the window")
                        self._superseded.add(self.owner["rappid"])
                        self.owner = {k: v for k, v in self.successor.items() if k != "name"}
                        self.successor = None
                        self.window = None
                        self.last_owner_utc = frame["utc"]
                        self.inherited = True
                if self.window is not None:
                    _stamp(self._deadlines()[1])
            head = frame

    def verify_signature(self, unsigned: dict, sig: str, expected_kid=None) -> tuple:
        """Resolve only public keys carried by verified succession nominations."""
        header, _, _ = R.parse_detached_jws(sig)
        der = self._keys.get(header["kid"])
        if der is None:
            return False, "no public key in the chain for this signer"
        return R.verify_detached_jws(unsigned, sig, der, expected_kid)

    def _deadlines(self) -> tuple:
        silence = (_instant(self.last_owner_utc, "last owner time")
                   + self.window["silence_days"] * DAY_MS)
        return silence, silence + self.window["confirm_days"] * DAY_MS

    def state(self, now_utc: str) -> dict:
        now = _instant(now_utc, "now_utc")
        silence = confirm = None
        status = "inherited" if self.inherited else "unnamed"
        if self.window is not None:
            silence, confirm = self._deadlines()
            status = "handoff-open" if now >= confirm else "silent" if now >= silence else "owned"
        return {
            "owner": self.owner["rappid"] if self.owner else None,
            "successor": ({k: self.successor[k] for k in ("name", "rappid")}
                          if self.successor else None),
            "last_owner_utc": self.last_owner_utc,
            "silence_deadline": _stamp(silence) if silence is not None else None,
            "confirm_deadline": _stamp(confirm) if confirm is not None else None,
            "status": status,
        }


def validate_chain(frames: Sequence[dict]) -> None:
    """Refuse any broken chain, signature, nomination, pulse, or handoff."""
    SuccessionChain(frames)


def state(frames: Sequence[dict], now_utc: str) -> dict:
    return SuccessionChain(frames).state(now_utc)


def load_chain(path: Path) -> list:
    raw = Path(path).read_bytes()
    if raw.lstrip().startswith(b"["):
        frames = R._strict_json(raw)
        require(isinstance(frames, list), "chain fixture: expected frame array")
        return frames
    return [R._strict_json(line) for line in raw.splitlines() if line.strip()]


def sign_frame(kind, stream_id, seq, utc, payload, prev, private_key_pem):
    """Sign an eleven-key frame; private key material is never retained."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    validate_payload(kind, payload)
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    require(isinstance(key, Ed25519PrivateKey), "signing requires an Ed25519 private key")
    der = key.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    if kind == "succession.name":
        rid = payload["owner"]["rappid"]
    else:
        # A pulse/handoff contains no signer identity; preserve the caller's
        # original rappid label alongside its PEM using SigningKey below.
        rid = getattr(private_key_pem, "rappid", None)
    require(isinstance(rid, str) and R.rappid_valid(rid)
            and R.rappid_parts(rid)["hash"] == R.Hb("rapp/1:rappid", der),
            "signing key needs its keyed rappid; use SigningKey(pem, rappid)")
    header = {"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": rid}
    protected = base64.urlsafe_b64encode(R.canonical(header).encode()).rstrip(b"=").decode()
    frame = R.build_frame(kind, stream_id, seq, utc, payload, prev)
    unsigned = {k: v for k, v in frame.items() if k != "sig"}
    signature = key.sign(protected.encode() + b"." + R.canonical(unsigned).encode())
    frame["sig"] = protected + ".." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return frame


class SigningKey(bytes):
    """Ephemeral PEM plus public identity; labels cannot be recovered from SPKI."""

    def __new__(cls, pem: bytes, rappid: str):
        value = super().__new__(cls, pem)
        value.rappid = rappid
        return value
