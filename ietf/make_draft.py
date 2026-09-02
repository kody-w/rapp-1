#!/usr/bin/env python3
"""make_draft.py — render SPEC.md into ietf/draft-wildfeuer-rapp-1-NN.md (kramdown-rfc source)."""
import re, sys, pathlib, json, hashlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
argv = [a for a in sys.argv[1:] if a != "--check"]
check = "--check" in sys.argv
version = argv[0] if argv else "00"
s = (ROOT / "SPEC.md").read_text(encoding="utf-8")
orient = json.loads((ROOT / "anchor" / "orient.json").read_text(encoding="utf-8"))
rev = orient["spec"]["revision"]; frame = orient["spec"]["revision_frame_hash"]
normative_sha = hashlib.sha256((ROOT / "SPEC.md").read_bytes()).hexdigest()
assert normative_sha == orient["spec"]["normative_sha256"], "SPEC.md is not the beacon's head; materialize first"
body = s[s.index("## 1. Introduction"):s.index("## 15. References")]
body = re.sub(r"^(#{2,4}) \d+(?:\.\d+)*\.? ", r"\1 ", body, flags=re.M)
body = re.sub(r"^#(#+) ", lambda m: "#" * len(m.group(1)) + " ", body, flags=re.M)
rfcs = sorted(set(re.findall(r"\[RFC (\d+)\]", body)))
body = re.sub(r"\[RFC (\d+)\]", lambda m: "{{RFC" + m.group(1) + "}}", body)
body = re.sub(r"\[(FIPS 180-4|ECMA-262|NIST SP 800-38D)\]", r"\1", body)
normrefs = "\n".join(f"  RFC{n}:" for n in rfcs)
doc = f"""---
title: "RAPP/1: The RAPP Protocol Suite"
abbrev: RAPP/1
docname: draft-wildfeuer-rapp-1-{version}
category: info
submissiontype: independent
ipr: trust200902
area: Applications
keyword: [agents, content-addressing, canonicalization, JCS, provenance]
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  -
    ins: K. Wildfeuer
    name: Kody Wildfeuer
    organization: Wildhaven Homes LLC
    email: wildhavenhomesllc@gmail.com

normative:
{normrefs}

informative:
  RAPP1-ANCHOR:
    title: "RAPP/1 specification anchor (append-only chain of record)"
    target: https://kody-w.github.io/rapp-1/anchor/orient.json
    date: 2026

--- abstract

RAPP/1 is a profile over existing standards that lets independent programs exchange
verifiable, content-addressed records about agents: one canonicalization (JCS), one
domain-separated hash, one mint-once identity, one eleven-key event envelope, one wire,
and one package format. Two independent implementations that follow this document
produce byte-identical artifacts with no out-of-band agreement. The normative text of
record is the append-only specification chain published by the author; this document
is a stable, archival rendering of it: revision {rev}, chain frame {frame}, normative
SHA-256 {normative_sha}. Any later revision supersedes this rendering; the chain, not
this document, says which is current.

--- middle

{body}

--- back

# Acknowledgements

The specification was hardened through adversarial review rounds recorded in its
revision log. The chain of record and its verifier are at {{{{RAPP1-ANCHOR}}}}.
"""
out = ROOT / "ietf" / f"draft-wildfeuer-rapp-1-{version}.md"
if check:
    current = out.read_text(encoding="utf-8") if out.exists() else ""
    if current != doc:
        print(f"{out.name} is stale: it does not render the chain head ({rev}). Run python3 ietf/make_draft.py {version}")
        sys.exit(1)
    print(f"{out.name} renders the chain head ({rev}, frame {frame[:12]}…)")
    sys.exit(0)
out.write_text(doc, encoding="utf-8")
print("wrote", out, "| RFC references:", len(rfcs), "| revision", rev)
