"""09 — The distributed Hive's LTS: pin every component, retire a member, let a key speak.

A distributed Hive is many repositories — a kernel, member organisms, the protocol text, and a
network organism whose pulse says the Hive is alive — held together by one estate registry (SPEC
§13). Three declared entries, each carrying the owner's own signature (§13.4), do the holding:
  - release pins (§13.5): a release scope names a release family bound to at most one Grail kernel;
    each immutable release of it is one `release-pin` naming a `rapp/1-release-manifest` by particle
    hash, and the manifest pins every component file by SHA-256 and length at an immutable commit
    and binds each member's door of record. A verified snapshot is exactly those files, or nothing.
  - lifecycle notices (§13.6): the estate says, and signs, that a member is superseded, and since when.
  - stream signers (§13.7): the estate says which key speaks for it on one stream.

This program builds a fictional estate, "acme": an LTS family (kernel 1.4.2, three files) with one
correction release; a newest channel that moves from the 2.0 family to the 2.1 family; keyless member
organisms bound as doors of record; a notice superseding one member; and the network organism's
body.pulse stream, unsigned at first, then spoken for by a granted crawler key.
Run: python3 examples/09_distributed_hive_lts.py

Nothing here is signed. Both registries are unsigned DRAFTS (§13.1): the reference loads them only
with allow_unsigned=True and snapshots them only with allow_draft=True, so every result below is a
rehearsal, never authority. The stand-in SPKI bytes are fingerprints for the rehearsal, not keys.
"""
import base64, copy, hashlib, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rapp as R
import rapp_registry as REG

def show(label, ok, why=""):
    print(f"  [{'OK' if ok else '--'}] {label}" + (f" — {why}" if why else ""))
    if not ok:
        raise SystemExit(1)

def short(text):
    return re.sub(r"([0-9a-f]{8})[0-9a-f]{56}", r"\1…", text)

def refused(label, attempt):
    try:
        attempt()
    except REG.RegistryError as why:
        return show(label, True, short(str(why)))
    show(label, False, "was accepted")

# ── 1. The estate's keys, and every repository as one in-memory transport. ──
def keyed(slug):
    der = f"stand-in SPKI bytes for acme/{slug}: a fingerprint, not a key".encode()
    rappid = R.mint_rappid("acme", slug, spki_der=der)
    return rappid, {"type": "spki", "rappid": rappid, "deprecated": False,
                    "spki_der_b64": base64.b64encode(der).decode("ascii")}

owner, owner_spki = keyed("estate-owner")
crawler, crawler_spki = keyed("hive-crawler")  # the key the owner will let speak on the pulse stream
station, station_spki = keyed("edge-station")  # a registered key the owner never grants
GIT = "https://git.example.test/acme/"
STORE = {}  # (repository, commit, path) -> octets: a git host, a mirror, a cache — all the same here

def fetch(repository, object_format, commit, path):
    """Any transport. Never trusted: every byte it returns is checked against the manifest."""
    return STORE[(repository, commit, path)]

# ── 2. Components: a kernel of three frozen files, and keyless members with doors of record. ──
KERNEL = "brainstem/brainstem.py"
def kernel_files(version):
    return {KERNEL: f'"""acme kernel entry point {version}."""\n'.encode(),
            "brainstem/agents/basic_agent.py": b"class BasicAgent:\n    pass\n",
            "brainstem/VERSION": f"{version}\n".encode()}

widget, ledger, ledger_next, network = (R.mint_rappid("acme", slug)  # keyless (§6.2): tails, not keys
                                        for slug in ("widget-factory", "ledger", "ledger-next", "network"))
def identity(rappid):
    return R.canonical({"schema": "rapp/1", "rappid": rappid}).encode("utf-8")

def component(cid, kind, commit, files, rappid=None, tag=None):
    """One component in repository GIT + cid, its files published at `commit` and pinned."""
    STORE.update({(GIT + cid, commit, path): octets for path, octets in files.items()})
    return {"id": cid, "kind": kind, "rappid": rappid, "identity_path": "rappid.json" if rappid else None,
            "repository": GIT + cid, "object_format": "sha1", "commit": commit, "immutable_ref": tag,
            "files": [{"path": p, "sha256": hashlib.sha256(o).hexdigest(), "size_bytes": len(o)}
                      for p, o in sorted(files.items(), key=lambda item: item[0].encode("utf-8"))]}

def manifest(scope, name, version, kernel_commit, widget_commit, books=("ledger", ledger, "4a" * 20)):
    """One release of the family `scope`, named `name` for people; its identity is its manifest_hash."""
    slug, books_rappid, books_commit = books
    return {"schema": REG.MANIFEST_SCHEMA, "release_scope": scope, "release": name, "components": [
        component("brainstem", "kernel", kernel_commit, kernel_files(version), tag=f"refs/tags/v{version}"),
        component(slug, "organism", books_commit,
                  {"rappid.json": identity(books_rappid), "soul.md": f"# {slug}\n".encode()}, rappid=books_rappid),
        component("network", "organism", "7a" * 20, {"rappid.json": identity(network)}, rappid=network),
        component("rapp-1", "protocol", "5a" * 20, {"SPEC.md": b"# the protocol text acme implements\n"},
                  tag="refs/tags/rev-17"),
        component("widget-factory", "organism", widget_commit, {"rappid.json": identity(widget),
                  "agents/widget_agent.py": f"# widget {widget_commit[:4]}\n".encode()}, rappid=widget)]}

# ── 3. The declared entries: kernels, release pins, lifecycle notices, and a grant. ──
LTS = "https://releases.example.test/acme/lts-1.4"  # the LTS family: kernel 1.4.2, forever
V2_0 = "https://releases.example.test/acme/2.0"     # the newest channel's first family: kernel 2.0.0
V2_1 = "https://releases.example.test/acme/2.1"     # the family it moves on to: kernel 2.1.0
FAMILIES = {LTS: "lts-1.4", V2_0: "2.0", V2_1: "2.1"}
RELEASES, RELEASES_COMMIT = GIT + "releases", "6a" * 20
NAMES = {}  # manifest_hash -> the manifest's `release`: for people, never for selection
SIGNED = {"declared_by": owner, "sig": "<owner-signed>"}  # a real estate signs each declared entry (§13.4)

def grail(scope, version, commit, activated):
    octets = kernel_files(version)[KERNEL]
    return {"type": "grail-kernel", "release_scope": scope, "grail_id": "grail:" + R.Hb("rapp/1:grail", octets),
            "repository": GIT + "brainstem", "immutable_ref": f"refs/tags/v{version}", "object_format": "sha1",
            "commit": commit, "path": KERNEL, "mode": "100644",
            "blob": hashlib.sha1(b"blob %d\0" % len(octets) + octets).hexdigest(),  # the git blob id
            "sha256": hashlib.sha256(octets).hexdigest(), "size_bytes": len(octets),
            "activated_utc": activated, "predecessor": None, **SIGNED}

def release_pin(release, channel, predecessor, activated):
    """Publish one release's manifest, exactly canonical(manifest), and declare its release-pin."""
    manifest_hash = R.H("rapp/1:particle", release)
    NAMES[manifest_hash] = release["release"]
    path = f"releases/{manifest_hash}.json"
    STORE[(RELEASES, RELEASES_COMMIT, path)] = R.canonical(release).encode("utf-8")
    return {"type": "release-pin", "release_scope": release["release_scope"], "channel": channel,
            "predecessor": None if predecessor is None else predecessor["manifest_hash"],
            "manifest_hash": manifest_hash, "repository": RELEASES, "object_format": "sha1",
            "commit": RELEASES_COMMIT, "path": path, "activated_utc": activated, **SIGNED}

def notice(rappid, state, since, activated, previous=None, superseded_by=None):
    return {"type": "lifecycle", "rappid": rappid, "state": state, "superseded_by": superseded_by,
            "since_utc": since, "previous": None if previous is None else REG.entry_hash(previous),
            "activated_utc": activated, **SIGNED}

def named(pin):
    return f"{NAMES[pin['manifest_hash']]}@{pin['manifest_hash'][:8]}"

SEPT, OCT, NOV = "2026-09-01T00:00:00.000Z", "2026-10-01T00:00:00.000Z", "2026-11-01T00:00:00.000Z"
lts_release = manifest(LTS, "lts-2026.09", "1.4.2", "1a" * 20, "3a" * 20)
lts_correction = manifest(LTS, "lts-2026.10", "1.4.2", "1a" * 20, "3b" * 20)  # a widget fix, the same kernel
newest_2_0 = manifest(V2_0, "acme-2.0.0", "2.0.0", "2a" * 20, "3a" * 20)
newest_2_1 = manifest(V2_1, "acme-2.1.0", "2.1.0", "2b" * 20, "3b" * 20,
                      books=("ledger-next", ledger_next, "4b" * 20))  # the 2.1 family moves to ledger-next
lts_1, new_1 = release_pin(lts_release, "lts", None, SEPT), release_pin(newest_2_0, "newest", None, SEPT)
ledger_active = notice(ledger, "active", SEPT, SEPT)
pulses = [R.build_frame("body.pulse", network, 0, "2026-09-15T00:00:00.000Z", {"hive": "acme", "beat": 0}, None)]
pulses.append(R.build_frame("body.pulse", network, 1, "2026-09-20T00:00:00.000Z", {"hive": "acme", "beat": 1},
                            pulses[0]["payload_hash"]))
september = [
    {"type": "estate_owner", "rappid": owner}, owner_spki, crawler_spki, station_spki,
    {"type": "kind", "kind": "body.pulse", "family": "body", "deprecated": False},
    {"type": "genesis", "stream_id": network, "frame_hash": pulses[0]["frame_hash"], "deprecated": False},
    grail(LTS, "1.4.2", "1a" * 20, SEPT), grail(V2_0, "2.0.0", "2a" * 20, SEPT),  # each before its first pin
    lts_1, new_1, ledger_active,
]
lts_2 = release_pin(lts_correction, "lts", lts_1, OCT)  # a correction supersedes; nothing is rebound
new_2 = release_pin(newest_2_1, "newest", new_1, OCT)   # the newest channel moves on to the next family
grant = {"type": "stream-signer", "stream_id": network, "signer": crawler, "kinds": ["body.pulse"],
         "since_utc": OCT, "until_utc": None, "activated_utc": OCT, **SIGNED}
october = september + [
    grail(V2_1, "2.1.0", "2b" * 20, OCT), lts_2, new_2,
    notice(ledger, "superseded", NOV, OCT, previous=ledger_active, superseded_by=ledger_next),  # from November
    grant,
]

def load(entries, seq):
    document = {"schema": "rapp/1-registry", "registry_seq": seq, "entries": entries, "sig": None,
                "canonical_source": "https://registry.example.test/acme/rapp-registry.json"}
    status, reg, why = REG.load_document(document, trust_anchor=owner, allow_unsigned=True)
    show(f"registry_seq {seq}: {len(entries)} entries load as a {status}",
         status == "draft" and reg.status == "draft", why)
    return reg

print("the estate registry — unsigned DRAFTS, so everything below is a rehearsal (§13.1):")
september_reg, reg = load(september, 1), load(october, 2)
kept = [e for e in september if e["type"] in REG.DECLARED_TYPES]  # what a consumer persists (§13.4)
show("the October registry retains every September declaration byte for byte",
     reg.check_retained(kept) == (True, "ok"))

# ── 4. Channels and families: a family's last release in chain order is its current release. ──
print("\nchannels (§13.5) — each one linear chain of release pins; its head pins the current release:")
for channel in sorted(reg.release_channels):
    show(f"{channel}: " + " -> ".join(named(e) for e in reg.release_channels[channel]), True,
         "head " + named(reg.channel_head(channel)))
for scope in (LTS, V2_0, V2_1):
    show(f"family {FAMILIES[scope]}: {len(reg.scope_releases(scope))} release(s)", True,
         "current " + named(reg.scope_head(scope)))
show("the LTS correction heads the lts channel; September's head was the first LTS release",
     reg.channel_head("lts") is lts_2 and september_reg.channel_head("lts") is lts_1)
show("newest crossed from the 2.0 family to the 2.1 family, and 2.0 keeps its current release",
     reg.channel_head("newest") is new_2 and reg.scope_head(V2_0) is new_1)
refused("pinning the LTS correction a second time: a release manifest is pinned once",
        lambda: REG.Registry(october + [release_pin(lts_correction, "lts", lts_2, NOV)]))
refused("a second correction of the first LTS release: a channel never forks", lambda: REG.Registry(
    october + [release_pin(manifest(LTS, "lts-2026.10-hotfix", "1.4.2", "1a" * 20, "3c" * 20), "lts", lts_1, OCT)]))

# ── 5. The verified snapshot of the LTS head: exactly the pinned files, or nothing. ──
print("\nverified snapshot of the lts head (§13.5):")
refused("a draft is not authority: no snapshot unless allow_draft=True rehearses it",
        lambda: REG.verify_snapshot(reg, fetch, channel="lts"))
calls = []
def recording(*locator):
    calls.append(locator)
    return fetch(*locator)
snapshot = REG.verify_snapshot(reg, recording, channel="lts", allow_draft=True)
show(f"{len(snapshot)} files, each length- and SHA-256-checked at its pinned commit", len(snapshot) == 9)
for (cid, path), octets in sorted(snapshot.items()):
    print(f"        {cid:15} {path:32} {len(octets):3} bytes")
show("the kernel's two companions ride with its entry point",
     {p for c, p in snapshot if c == "brainstem"} == set(kernel_files("1.4.2")))
show("the transport was asked only for the manifest and pinned commits — never a moving branch",
     len(calls) == 10 and all(len(call[2]) == 40 for call in calls))
first = REG.verify_snapshot(reg, fetch, manifest_hash=lts_1["manifest_hash"], allow_draft=True)
WIDGET_AGENT = ("widget-factory", "agents/widget_agent.py")
show("the superseded first LTS release still verifies by its manifest_hash, on the same kernel bytes",
     all(first[key] == snapshot[key] for key in snapshot if key[0] == "brainstem")
     and first[WIDGET_AGENT] != snapshot[WIDGET_AGENT])
newest = REG.verify_snapshot(reg, fetch, channel="newest", allow_draft=True)
show("the newest head runs the 2.1 kernel", newest[("brainstem", KERNEL)] == kernel_files("2.1.0")[KERNEL])
def tampered(replace):
    def transport(repository, object_format, commit, path):
        octets = fetch(repository, object_format, commit, path)
        return replace(octets) if path == "agents/widget_agent.py" else octets
    return transport
refused("one member file with one injected line refuses the whole snapshot", lambda: REG.verify_snapshot(
    reg, tampered(lambda o: o + b"import os\n"), channel="lts", allow_draft=True))
refused("so does a file of the same length with other bytes", lambda: REG.verify_snapshot(
    reg, tampered(lambda o: o.upper()), channel="lts", allow_draft=True))

# ── 6. A door of record is the manifest's binding, never a copy found elsewhere. ──
print("\ndoors of record (§13.5):")
MONOREPO = GIT + "monorepo"
STORE[(MONOREPO, "8a" * 20, "organisms/widget-factory/rappid.json")] = identity(widget)  # byte-identical copy
pinned = REG.verify_release_manifest(reg, lts_2, fetch(RELEASES, "sha1", RELEASES_COMMIT, lts_2["path"]))
doors = {c["rappid"]: c["repository"] for c in pinned["components"] if c["rappid"]}
show("each keyless member's door of record is the repository its release binds",
     doors == {widget: GIT + "widget-factory", ledger: GIT + "ledger", network: GIT + "network"})
show("the monorepo's identical rappid.json is only a copy: never fetched, never a door",
     all(call[0] != MONOREPO for call in calls))
rebound = copy.deepcopy(pinned)
door = next(c for c in rebound["components"] if c["rappid"] == widget)
door.update(repository=MONOREPO, commit="8a" * 20, identity_path="organisms/widget-factory/rappid.json",
            files=component("monorepo", "organism", "8a" * 20, {"organisms/widget-factory/rappid.json":
                                                                  identity(widget)})["files"])
REG.validate_release_manifest(rebound)  # well-formed — but not what the owner pinned
def hostile_mirror(repository, object_format, commit, path):
    if (repository, path) == (RELEASES, lts_2["path"]):
        return R.canonical(rebound).encode("utf-8")
    return fetch(repository, object_format, commit, path)
refused("a mirror serving a manifest that makes the monorepo the door is refused",
        lambda: REG.verify_snapshot(reg, hostile_mirror, channel="lts", allow_draft=True))

# ── 7. A lifecycle notice supersedes one member, from its since_utc on. ──
print("\nlifecycle notices (§13.6):")
for utc, state, successor in (("2026-10-15T00:00:00.000Z", "active", None), (NOV, "superseded", ledger_next)):
    show(f"ledger at {utc[:10]}: {state}" + (" by ledger-next" if successor else ""),
         reg.lifecycle_state_at(ledger, utc) == state and reg.successor_at(ledger, utc) == successor)
show("declared on 1 October, the notice is current before it is in effect",
     reg.lifecycle_head(ledger)["since_utc"] == NOV and reg.lifecycle_state_at(ledger, OCT) == "active")
show("a member with no notice has no declared lifecycle — never a guessed deprecation",
     reg.lifecycle_state_at(widget, NOV) is None)
show("the LTS head still pins ledger and the 2.1 family carries ledger-next: a notice rebinds no release",
     ("ledger", "soul.md") in snapshot and ("ledger-next", "soul.md") in newest)
refused("ledger-next superseded by ledger from the same day: the successors in effect never loop",
        lambda: REG.Registry(october + [notice(ledger_next, "superseded", NOV, OCT, superseded_by=ledger)]))

# ── 8. The network organism's pulse: unsigned first, then spoken for by a granted key. ──
print("\nthe network organism's body.pulse stream (§13.7):")
for pulse, head in zip(pulses, [None] + pulses):
    ok, step, why = reg.verify_authorized_frame(pulse, head=head, stream_id_of_record=network)
    show(f"unsigned pulse {pulse['seq']} is a valid rapp/1 frame that does not speak for the estate",
         (ok, step) == (False, "authority"), why)
later = [pulses[1]]
for seq, utc in ((2, "2026-10-15T00:00:00.000Z"), (3, "2026-10-20T00:00:00.000Z")):
    later.append(R.build_frame("body.pulse", network, seq, utc, {"hive": "acme", "beat": seq},
                               later[-1]["payload_hash"]))
show("the crawler's pulses extend the same chain", all(
    R.verify_frame(p, head=h, stream_id_of_record=network)[0] for h, p in zip(later, later[1:])))
show("a signature changes neither hash (§7.3), so signing them keeps every link", all(
    R.build_frame(p["kind"], network, p["seq"], p["utc"], p["payload"], p["prev"], sig="<crawler JWS>")
    == dict(p, sig="<crawler JWS>") for p in later[1:]))
print("        (signing needs the crawler's real key; this rehearsal asks authority_decision about each\n"
      "         pulse's stream, kid, kind, and utc — what verify_authorized_frame asks once §7.5 step 6\n"
      "         has verified the signature)")
def speaks(registry, kid, pulse):
    return registry.authority_decision(network, kid, pulse["kind"], pulse["utc"])
for pulse in later[1:]:
    ok, why = speaks(reg, crawler, pulse)
    show(f"pulse {pulse['seq']}, signed by the granted crawler, speaks for the estate", ok, why)
ok, why = speaks(september_reg, crawler, later[1])
show("against the September registry it did not: a cached refusal is re-evaluated against a newer one", not ok,
     why)
ok, why = speaks(reg, station, later[1])
show("the station's key is registered, yet it does not speak for the estate on this stream", not ok, why)
ok, why = speaks(reg, crawler, pulses[1])
show("the grant starts at its since_utc: before it, even a crawler-signed pulse would not speak", not ok, why)
show("the estate owner in effect needs no grant", speaks(reg, owner, later[1]) == (True, "estate owner"))

print("\nSeeds, beacons, Hive indexes, and moving branches may say where to look; only what a release"
      "\nmanifest pins is part of a verified snapshot, only a verified notice says a member is superseded,"
      "\nand only the owner or a granted key speaks for the estate on a stream.")
