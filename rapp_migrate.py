"""rapp_migrate.py — re-anchor a legacy rappid.json into RAPP compliance.

The migration is DETERMINISTIC and identity-preserving: it derives the new
domain-tagged 64-hex tail from the SAME underlying UUID anchor the legacy identity
already used, so the organism keeps its identity — only the encoding becomes
compliant (§5/§6.2). The old rappid string is recorded in `_migrated_from` so every
existing reference resolves forward (§6.3 re-anchor). Schema label → 'rapp/1' (§12).

  legacy tail (32-hex UUID, or _legacy_uuid)  →  Hb("rapp/1:rappid", uuid_bytes)

Usage:
  python3 rapp_migrate.py <rappid.json> [--write]      # re-anchor one record
  import rapp_migrate; new = rapp_migrate.reanchor(dict)   # library form

Without --write it prints the proposed new record (dry run).
"""
import json
import re
import sys
import uuid as _uuid

import rapp as R

_32HEX = re.compile(r"^[0-9a-f]{32}$")
_64HEX = re.compile(r"^[0-9a-f]{64}$")


def _anchor_bytes(d, tail):
    """Recover the 16-byte UUID anchor this identity was minted from."""
    for k in ("_legacy_uuid", "_legacy_uuid_note"):
        v = d.get(k, "")
        m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", str(v))
        if m:
            return _uuid.UUID(m.group(0)).bytes
    if _32HEX.match(tail or ""):                    # the 32-hex tail IS the stripped UUID
        return bytes.fromhex(tail)
    if _64HEX.match(tail or ""):
        # already 64-hex but minted untagged sha256(uuid); recover uuid from _legacy_uuid only
        raise ValueError("64-hex tail with no recoverable UUID anchor — needs explicit _legacy_uuid")
    raise ValueError(f"no recoverable anchor for tail {tail!r}")


def reanchor(d):
    """Return (new_record, mapping) where mapping = {old_rappid: new_rappid}. Idempotent."""
    d = dict(d)
    old = d.get("rappid", "")
    # already compliant grammar AND already tagged? leave the tail, just fix schema label.
    owner = slug = None
    m = R._RAPPID.match(old)
    if m:
        owner, slug, tail = m.group(1), m.group(2), m.group(3)
    else:
        # legacy self-locating or bare form: pull owner/slug from fields or the string
        owner = d.get("owner") or (old.split("@", 1)[1].split("/", 1)[0] if "@" in old else None)
        slug = d.get("repo") or d.get("name")
        tm = re.search(r"([0-9a-f]{32}|[0-9a-f]{64})", old)
        tail = tm.group(1) if tm else None
    if not owner or not slug:
        raise ValueError(f"cannot determine owner/slug for {old!r}")

    # is the current tail already a proper domain-tagged mint we can keep?
    keep_tail = False
    if m and _64HEX.match(tail):
        # Only keep if we cannot prove it was untagged. If _legacy_uuid is present we
        # re-anchor to the tagged form; otherwise assume it is already the tagged mint.
        keep_tail = not any(k.startswith("_legacy_uuid") for k in d)

    if keep_tail:
        new_tail = tail
    else:
        anchor = _anchor_bytes(d, tail)
        new_tail = R.Hb("rapp/1:rappid", anchor)

    new_rappid = f"rappid:@{owner}/{slug}:{new_tail}"
    if new_rappid != old and old:
        mf = d.get("_migrated_from")
        chain = mf if isinstance(mf, list) else ([mf] if mf else [])
        if old not in chain:
            chain = [old] + chain
        d["_migrated_from"] = chain if len(chain) > 1 else chain[0]
    d["rappid"] = new_rappid
    d["schema"] = "rapp/1"
    return d, ({old: new_rappid} if old and old != new_rappid else {})


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    write = "--write" in sys.argv
    if not args:
        print("usage: python3 rapp_migrate.py <rappid.json> [--write]"); sys.exit(2)
    path = args[0]
    d = json.load(open(path))
    new, mapping = reanchor(d)
    verdict = "unchanged" if not mapping and new.get("schema") == d.get("schema") else "re-anchored"
    print(f"# {path}  ({verdict})")
    if mapping:
        for o, n in mapping.items():
            print(f"#   {o}\n#   → {n}")
    print(json.dumps(new, indent=2, ensure_ascii=False))
    # verify the result is compliant grammar
    assert R.rappid_valid(new["rappid"]), "migration produced an invalid rappid!"
    if write:
        json.dump(new, open(path, "w"), indent=2, ensure_ascii=False)
        open(path, "a").write("\n")
        print(f"# WROTE {path}")


if __name__ == "__main__":
    main()
