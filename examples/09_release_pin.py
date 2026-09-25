"""09 — Release pins. Every component of a release, verified together or not at all.

An estate's kernel, organisms, and protocol text live in many repositories. A release pins
all of them at once (SPEC §13.5). A release scope names a release family bound to at most one
Grail kernel, forever; each immutable release of the family is one `release-pin` registry
entry that pins one `rapp/1-release-manifest` by particle hash, and the manifest pins every
component file by SHA-256 and length at an immutable commit. A consumer then builds a
*verified snapshot* of one release: exactly the pinned files, or nothing. Releases form
channels: a channel's head is its current release, a correction is a new release appended
to its family's channel, and every earlier release stays verifiable by its manifest_hash.

This program builds a fictional estate ("acme"): an LTS family (kernel 1.4.2) whose channel
appends one correction that keeps the kernel, and a newest channel that moves on from the
2.0 family to the 2.1 family. Each release has a three-file kernel, two organisms, and the
protocol text; everything is snapshotted through an in-memory transport.
Run: python3 examples/09_release_pin.py

Nothing here is signed. The registry is an unsigned DRAFT (§13.1): the reference loads it
only with allow_unsigned=True and snapshots it only with allow_draft=True, so every result
below is a rehearsal, never authority. The stand-in SPKI bytes are not a key.
"""
import base64, copy, hashlib, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rapp as R
import rapp_registry as REG

def show(label, ok, why=""):
    print(f"  [{'OK' if ok else '--'}] {label}" + (f" — {why}" if why else ""))
    if not ok:
        raise SystemExit(1)

def refused(label, attempt):
    try:
        attempt()
    except REG.RegistryError as why:
        show(label, True, re.sub(r"([0-9a-f]{8})[0-9a-f]{56}", r"\1…", str(why)))
        return
    show(label, False, "was accepted")

# ── 1. The owner, and every repository as one in-memory transport. ──
OWNER_SPKI = b"stand-in SPKI bytes: not a key, only its fingerprint matters here"
owner = R.mint_rappid("acme", "estate-owner", spki_der=OWNER_SPKI)
GIT = "https://git.example.test/acme/"
STORE = {}  # (repository, commit, path) -> octets: a git host, a mirror, a cache — all the same to us

def fetch(repository, object_format, commit, path):
    """Any transport. Never trusted: every byte it returns is checked against the manifest."""
    return STORE[(repository, commit, path)]

def pinned(repository, commit, files):
    STORE.update({(repository, commit, path): octets for path, octets in files.items()})
    return [{"path": p, "sha256": hashlib.sha256(o).hexdigest(), "size_bytes": len(o)}
            for p, o in sorted(files.items(), key=lambda item: item[0].encode("utf-8"))]

def component(cid, kind, repo, commit, files, rappid=None, identity_path=None, tag=None):
    return {"id": cid, "kind": kind, "rappid": rappid, "identity_path": identity_path,
            "repository": GIT + repo, "object_format": "sha1", "commit": commit,
            "immutable_ref": tag, "files": pinned(GIT + repo, commit, files)}

# ── 2. Components. The kernel is three frozen files; each organism has a door of record. ──
KERNEL = "brainstem/brainstem.py"
def kernel_files(version):
    return {KERNEL: f'"""acme kernel entry point {version}."""\n'.encode(),
            "brainstem/agents/basic_agent.py": b"class BasicAgent:\n    pass\n",
            "brainstem/VERSION": f"{version}\n".encode()}

widget, ledger = R.mint_rappid("acme", "widget-factory"), R.mint_rappid("acme", "ledger")  # keyless
def identity(rappid):
    return R.canonical({"schema": "rapp/1", "rappid": rappid}).encode("utf-8")

def manifest(scope, version, kernel_commit, widget_commit):
    return {"schema": REG.MANIFEST_SCHEMA, "release_scope": scope, "components": [
        component("acme-kernel", "kernel", "brainstem", kernel_commit, kernel_files(version), tag=f"refs/tags/v{version}"),
        component("ledger", "organism", "ledger", "4a" * 20, {"rappid.json": identity(ledger), "soul.md": b"# ledger\n"},
                  rappid=ledger, identity_path="rappid.json"),
        component("rapp-1", "protocol", "protocol", "5a" * 20, {"SPEC.md": b"# the protocol text acme implements\n"},
                  tag="refs/tags/rev-17"),
        component("widget-factory", "organism", "widget-factory", widget_commit,
                  {"rappid.json": identity(widget), "agents/widget_agent.py": f"# widget agent {widget_commit[:4]}\n".encode()},
                  rappid=widget, identity_path="rappid.json"),
    ]}

# ── 3. Release families, each with its one kernel, and their releases in two channels. ──
LTS = "https://releases.example.test/acme/1.4"   # the LTS family: kernel 1.4.2, forever
V2_0 = "https://releases.example.test/acme/2.0"  # a newest family: kernel 2.0.0
V2_1 = "https://releases.example.test/acme/2.1"  # the family the newest channel moves on to: kernel 2.1.0
NAMES = {LTS: "1.4", V2_0: "2.0", V2_1: "2.1"}
RELEASES, RELEASES_COMMIT = GIT + "releases", "6a" * 20

def grail(scope, version, commit, activated, predecessor=None):
    octets = kernel_files(version)[KERNEL]
    return {"type": "grail-kernel", "release_scope": scope, "grail_id": "grail:" + R.Hb("rapp/1:grail", octets),
            "repository": GIT + "brainstem", "immutable_ref": f"refs/tags/v{version}", "object_format": "sha1",
            "commit": commit, "path": KERNEL, "mode": "100644",
            "blob": hashlib.sha1(b"blob %d\0" % len(octets) + octets).hexdigest(),  # the git blob id
            "sha256": hashlib.sha256(octets).hexdigest(), "size_bytes": len(octets),
            "activated_utc": activated, "predecessor": predecessor, "declared_by": owner, "sig": "<owner-signed>"}

def release_pin(release, channel, predecessor, activated):
    """Publish one release's manifest, exactly canonical(manifest), and declare the release-pin for it."""
    manifest_hash = R.H("rapp/1:particle", release)
    path = f"releases/{manifest_hash}.json"
    STORE[(RELEASES, RELEASES_COMMIT, path)] = R.canonical(release).encode("utf-8")
    return {"type": "release-pin", "release_scope": release["release_scope"], "channel": channel,
            "predecessor": None if predecessor is None else predecessor["manifest_hash"],
            "manifest_hash": manifest_hash, "repository": RELEASES, "object_format": "sha1",
            "commit": RELEASES_COMMIT, "path": path, "activated_utc": activated, "declared_by": owner,
            "sig": "<owner-signed>"}

def named(pin):
    return f"{NAMES[pin['release_scope']]}@{pin['manifest_hash'][:8]}"

SEPT, OCT = "2026-09-01T00:00:00.000Z", "2026-10-01T00:00:00.000Z"
lts_release = manifest(LTS, "1.4.2", "1a" * 20, "3a" * 20)
lts_correction = manifest(LTS, "1.4.2", "1a" * 20, "3b" * 20)  # a widget fix; the same kernel, byte for byte
newest_2_0 = manifest(V2_0, "2.0.0", "2a" * 20, "3a" * 20)
newest_2_1 = manifest(V2_1, "2.1.0", "2b" * 20, "3b" * 20)
kernels = [grail(LTS, "1.4.2", "1a" * 20, SEPT), grail(V2_0, "2.0.0", "2a" * 20, SEPT)]
kernels.append(grail(V2_1, "2.1.0", "2b" * 20, OCT, predecessor=kernels[1]["grail_id"]))
lts_1 = release_pin(lts_release, "lts", None, SEPT)
new_1 = release_pin(newest_2_0, "newest", None, SEPT)
lts_2 = release_pin(lts_correction, "lts", lts_1, OCT)       # a correction appends; nothing is rebound
new_2 = release_pin(newest_2_1, "newest", new_1, OCT)        # the newest channel moves on to the next family
entries = [
    {"type": "estate_owner", "rappid": owner},
    {"type": "spki", "rappid": owner, "deprecated": False, "spki_der_b64": base64.b64encode(OWNER_SPKI).decode("ascii")},
    *kernels,  # each family's kernel precedes its first release
    lts_1, new_1, lts_2, new_2,
]
document = {"schema": "rapp/1-registry", "registry_seq": 1,
            "canonical_source": "https://registry.example.test/acme/rapp-registry.json", "entries": entries, "sig": None}
status, reg, why = REG.load_document(document, trust_anchor=owner, allow_unsigned=True)
print("registry:", status, "—", why); assert status == "draft"
print("\nchannels (§13.5) — each one linear chain of releases; its head is the current release:")
for channel in sorted(reg.release_channels):
    chain = " -> ".join(named(e) for e in reg.release_channels[channel])
    show(f"{channel}: {chain}", True, "head " + named(reg.channel_head(channel)))
print("\nfamilies — one kernel each; a family's last release in chain order is its current release:")
for scope in (LTS, V2_0, V2_1):
    show(f"{NAMES[scope]}: {len(reg.scope_releases(scope))} release(s)", True, "current " + named(reg.scope_head(scope)))
show("the lts head is the correction, and so is the LTS family's current release",
     reg.channel_head("lts") is lts_2 and reg.scope_head(LTS) is lts_2)
show("newest moved on to the 2.1 family; the 2.0 family keeps its current release",
     reg.channel_head("newest") is new_2 and reg.scope_head(V2_0) is new_1)

# ── 4. The verified snapshot of the lts head: exactly the pinned files. ──
print("\nverified snapshot of the lts head:")
refused("a draft registry is not authority: no snapshot unless allow_draft=True rehearses it",
        lambda: REG.verify_snapshot(reg, fetch, channel="lts"))
calls = []
def recording(*locator):
    calls.append(locator)
    return fetch(*locator)
snapshot = REG.verify_snapshot(reg, recording, channel="lts", allow_draft=True)
show(f"{len(snapshot)} files, each length- and SHA-256-checked at its pinned commit", len(snapshot) == 8)
for (cid, path), octets in sorted(snapshot.items()):
    print(f"        {cid:15} {path:34} {len(octets):3} bytes")
show("the kernel's two companions ride with its entry point",
     {p for c, p in snapshot if c == "acme-kernel"} == set(kernel_files("1.4.2")))
show("the transport was asked only for the manifest and the pinned commits — never a moving branch",
     len(calls) == 9 and all(len(call[2]) == 40 for call in calls))
show("selecting the LTS family's current release yields the same snapshot",
     REG.verify_snapshot(reg, fetch, release_scope=LTS, allow_draft=True) == snapshot)
original = REG.verify_snapshot(reg, fetch, manifest_hash=lts_1["manifest_hash"], allow_draft=True)
def kernel_of(files):
    return {key: octets for key, octets in files.items() if key[0] == "acme-kernel"}
show("the original LTS release still verifies by its manifest_hash, on the same kernel bytes",
     kernel_of(original) == kernel_of(snapshot)
     and original[("widget-factory", "agents/widget_agent.py")] != snapshot[("widget-factory", "agents/widget_agent.py")])
newest = REG.verify_snapshot(reg, fetch, channel="newest", allow_draft=True)
show("the newest head runs the 2.1 kernel", newest[("acme-kernel", KERNEL)] == kernel_files("2.1.0")[KERNEL])
refused("a snapshot selects exactly one release", lambda: REG.verify_snapshot(
    reg, fetch, release_scope=LTS, channel="lts", allow_draft=True))

# ── 5. The door of record is the manifest's binding, not a copy found elsewhere. ──
print("\ndoor of record (§13.5):")
MONOREPO = GIT + "monorepo"
STORE[(MONOREPO, "8a" * 20, "organisms/widget-factory/rappid.json")] = identity(widget)  # a byte-identical copy
pin = reg.channel_head("lts")
bound = REG.verify_release_manifest(reg, pin, fetch(pin["repository"], pin["object_format"], pin["commit"], pin["path"]))
door = next(c for c in bound["components"] if c["rappid"] == widget)
show("widget-factory's door of record in the lts head is the repository the manifest binds",
     door["repository"] == GIT + "widget-factory", f"{door['repository']} @ {door['commit'][:12]}")
show("the monorepo's identical rappid.json is only a copy: never fetched, never the door",
     all(call[0] != MONOREPO for call in calls))
rebound = copy.deepcopy(bound)
for c in rebound["components"]:
    if c["rappid"] == widget:
        c.update(repository=MONOREPO, commit="8a" * 20, identity_path="organisms/widget-factory/rappid.json",
                 files=pinned(MONOREPO, "8a" * 20, {"organisms/widget-factory/rappid.json": identity(widget)}))
REG.validate_release_manifest(rebound)  # well-formed — but not what the owner pinned
def hostile_mirror(repository, object_format, commit, path):
    if (repository, commit, path) == (pin["repository"], pin["commit"], pin["path"]):
        return R.canonical(rebound).encode("utf-8")
    return fetch(repository, object_format, commit, path)
refused("a mirror serving a manifest that makes itself the door of record is refused",
        lambda: REG.verify_snapshot(reg, hostile_mirror, channel="lts", allow_draft=True))

# ── 6. All or nothing, one kernel per family, and nothing ever rebound. ──
print("\nrefusals (whole, never partial):")
def tampered(replace):
    def transport(repository, object_format, commit, path):
        octets = fetch(repository, object_format, commit, path)
        return replace(octets) if path == "agents/widget_agent.py" else octets
    return transport
refused("a member file with one injected line", lambda: REG.verify_snapshot(
    reg, tampered(lambda o: o + b"import os\n"), channel="lts", allow_draft=True))
refused("a member file with the same length and other bytes", lambda: REG.verify_snapshot(
    reg, tampered(lambda o: o.upper()), channel="lts", allow_draft=True))
show("the newest head's manifest is coherent with its family's grail-kernel",
     REG.check_kernel_coherence(reg, newest_2_1) == (True, "ok"))
ok, why = REG.check_kernel_coherence(reg, dict(newest_2_1, components=[newest_2_0["components"][0]] + newest_2_1["components"][1:]))
show("a 2.1 release carrying the 2.0 kernel instead is incoherent (kernel coherence)", not ok, why)
drifted = release_pin(manifest(LTS, "1.4.3", "1b" * 20, "3b" * 20), "lts", lts_2, OCT)
_, drift_registry, _ = REG.load_document(dict(document, entries=entries + [drifted]), trust_anchor=owner,
                                         allow_unsigned=True)
refused("an LTS correction with other kernel bytes cannot verify: a new kernel is a new family",
        lambda: REG.verify_snapshot(drift_registry, fetch, channel="lts", allow_draft=True))
refused("the LTS correction pinned a second time: a release is pinned once",
        lambda: REG.Registry(entries + [release_pin(lts_correction, "lts", lts_2, OCT)]))
another_fix = manifest(LTS, "1.4.2", "1a" * 20, "3c" * 20)
refused("a second correction of the first LTS release: a channel never forks",
        lambda: REG.Registry(entries + [release_pin(another_fix, "lts", lts_1, OCT)]))
refused("an LTS correction appended to the newest channel: a family lives in one channel",
        lambda: REG.Registry(entries + [release_pin(another_fix, "newest", new_2, OCT)]))
V2_2 = "https://releases.example.test/acme/2.2"
refused("a kernel declared after its family's first release: a family's kernel comes first",
        lambda: REG.Registry(entries + [release_pin(manifest(V2_2, "2.2.0", "2c" * 20, "3b" * 20), "newest", new_2, OCT),
                                        grail(V2_2, "2.2.0", "2c" * 20, OCT)]))

print("\nSeeds, beacons, Hive indexes, and moving branches may say where to look;"
      "\nonly what a release manifest pins is part of a verified snapshot.")
