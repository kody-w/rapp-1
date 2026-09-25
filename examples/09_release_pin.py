"""09 — Release pins. Every component of a release, verified together or not at all.

An estate's kernel, organisms, and protocol text live in many repositories. A release
scope pins all of them at once (SPEC §13.5): the owner declares one `release-pin` registry
entry per scope; it pins one `rapp/1-release-manifest` by particle hash; the manifest pins
every component file by SHA-256 and length at an immutable commit. A consumer then builds
a *verified snapshot*: exactly the pinned files, or nothing. Scopes form channels, and a
channel's head is its current release.

This program builds a fictional estate ("acme") with an LTS channel of two scopes and a
newest channel of one, each with a three-file kernel, two organisms, and the protocol
text, and snapshots them through an in-memory transport.
Run: python3 examples/09_release_pin.py

Nothing here is signed. The registry is an unsigned DRAFT (§13.1): the reference loads it
only with allow_unsigned=True and snapshots it only with allow_draft=True, so every result
below is a rehearsal, never authority. The stand-in SPKI bytes are not a key.
"""
import base64, copy, hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rapp as R
import rapp_registry as REG

def show(label, ok, why=""):
    print(f"  [{'OK' if ok else '--'}] {label}" + (f" — {why}" if why else ""))

def refused(label, attempt):
    try:
        attempt()
    except REG.RegistryError as why:
        show(label, True, str(why)[:120])
        return
    show(label, False, "was accepted"); raise SystemExit(1)

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

# ── 3. The registry: a grail-kernel and a release-pin per scope, in two channels. ──
LTS_1, LTS_2 = "https://releases.example.test/acme/lts/2026-09", "https://releases.example.test/acme/lts/2026-10"
NEWEST = "https://releases.example.test/acme/newest/2026-10"
RELEASES, RELEASES_COMMIT = GIT + "releases", "6a" * 20

def grail(scope, version, commit, activated, predecessor=None):
    octets = kernel_files(version)[KERNEL]
    return {"type": "grail-kernel", "release_scope": scope, "grail_id": "grail:" + R.Hb("rapp/1:grail", octets),
            "repository": GIT + "brainstem", "immutable_ref": f"refs/tags/v{version}", "object_format": "sha1",
            "commit": commit, "path": KERNEL, "mode": "100644",
            "blob": hashlib.sha1(b"blob %d\0" % len(octets) + octets).hexdigest(),  # the git blob id
            "sha256": hashlib.sha256(octets).hexdigest(), "size_bytes": len(octets),
            "activated_utc": activated, "predecessor": predecessor, "declared_by": owner, "sig": "<owner-signed>"}

def release_pin(scope, channel, predecessor, release, activated):
    path = "releases/" + scope.rsplit("/acme/", 1)[1].replace("/", "-") + ".json"
    STORE[(RELEASES, RELEASES_COMMIT, path)] = R.canonical(release).encode("utf-8")  # exactly canonical(manifest)
    return {"type": "release-pin", "release_scope": scope, "channel": channel, "predecessor": predecessor,
            "manifest_hash": R.H("rapp/1:particle", release), "repository": RELEASES, "object_format": "sha1",
            "commit": RELEASES_COMMIT, "path": path, "activated_utc": activated, "declared_by": owner,
            "sig": "<owner-signed>"}

SEPT, OCT = "2026-09-01T00:00:00.000Z", "2026-10-01T00:00:00.000Z"
lts_1 = manifest(LTS_1, "1.4.2", "1a" * 20, "3a" * 20)
lts_2 = manifest(LTS_2, "1.4.3", "1b" * 20, "3b" * 20)  # an LTS patch: new kernel bytes, a widget fix
newest = manifest(NEWEST, "2.0.0", "2a" * 20, "3b" * 20)
lts_grail = grail(LTS_1, "1.4.2", "1a" * 20, SEPT)
entries = [
    {"type": "estate_owner", "rappid": owner},
    {"type": "spki", "rappid": owner, "deprecated": False, "spki_der_b64": base64.b64encode(OWNER_SPKI).decode("ascii")},
    lts_grail, grail(LTS_2, "1.4.3", "1b" * 20, OCT, predecessor=lts_grail["grail_id"]), grail(NEWEST, "2.0.0", "2a" * 20, OCT),
    release_pin(LTS_1, "lts", None, lts_1, SEPT), release_pin(LTS_2, "lts", LTS_1, lts_2, OCT),
    release_pin(NEWEST, "newest", None, newest, OCT),
]
document = {"schema": "rapp/1-registry", "registry_seq": 1,
            "canonical_source": "https://registry.example.test/acme/rapp-registry.json", "entries": entries, "sig": None}
status, reg, why = REG.load_document(document, trust_anchor=owner, allow_unsigned=True)
print("registry:", status, "—", why); assert status == "draft"
print("\nchannels (§13.5) — each one linear chain; its head is the current release scope:")
for channel in sorted(reg.release_channels):
    chain = [e["release_scope"].rsplit("/acme/", 1)[1] for e in reg.release_channels[channel]]
    show(f"{channel}: {' -> '.join(chain)}", True, "head " + reg.channel_head(channel)["release_scope"])
assert reg.channel_head("lts")["release_scope"] == LTS_2

# ── 4. The verified snapshot of the LTS head: exactly the pinned files. ──
print("\nverified snapshot of the lts head:")
refused("a draft registry is not authority: no snapshot unless allow_draft=True rehearses it",
        lambda: REG.verify_snapshot(reg, LTS_2, fetch))
calls = []
def recording(*locator):
    calls.append(locator)
    return fetch(*locator)
snapshot = REG.verify_snapshot(reg, LTS_2, recording, allow_draft=True)
show(f"{len(snapshot)} files, each length- and SHA-256-checked at its pinned commit", len(snapshot) == 8)
for (cid, path), octets in sorted(snapshot.items()):
    print(f"        {cid:15} {path:34} {len(octets):3} bytes")
show("the kernel's two companions ride with its entry point",
     {p for c, p in snapshot if c == "acme-kernel"} == set(kernel_files("1.4.3")))
show("the transport was asked only for the manifest and the pinned commits — never a moving branch",
     len(calls) == 9 and all(len(call[2]) == 40 for call in calls))

# ── 5. The door of record is the manifest's binding, not a copy found elsewhere. ──
print("\ndoor of record (§13.5):")
MONOREPO = GIT + "monorepo"
STORE[(MONOREPO, "8a" * 20, "organisms/widget-factory/rappid.json")] = identity(widget)  # a byte-identical copy
pin = reg.release_pin(LTS_2)
bound = REG.verify_release_manifest(reg, LTS_2, fetch(pin["repository"], pin["object_format"], pin["commit"], pin["path"]))
door = next(c for c in bound["components"] if c["rappid"] == widget)
show("widget-factory's door of record in lts/2026-10 is the repository the manifest binds",
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
        lambda: REG.verify_snapshot(reg, LTS_2, hostile_mirror, allow_draft=True))

# ── 6. All or nothing: one bad byte anywhere refuses the whole snapshot. ──
print("\nrefusals (whole, never partial):")
def tampered(replace):
    def transport(repository, object_format, commit, path):
        octets = fetch(repository, object_format, commit, path)
        return replace(octets) if path == "agents/widget_agent.py" else octets
    return transport
refused("a member file with one injected line", lambda: REG.verify_snapshot(
    reg, LTS_2, tampered(lambda o: o + b"import os\n"), allow_draft=True))
refused("a member file with the same length and other bytes", lambda: REG.verify_snapshot(
    reg, LTS_2, tampered(lambda o: o.upper()), allow_draft=True))
show("the newest manifest is coherent with its scope's grail-kernel", REG.check_kernel_coherence(reg, newest) == (True, "ok"))
ok, why = REG.check_kernel_coherence(reg, dict(newest, components=[lts_1["components"][0]] + newest["components"][1:]))
show("a newest manifest pinning the LTS kernel instead is incoherent (kernel coherence)", not ok, why); assert not ok
refused("a second release-pin for lts/2026-09: a release scope is never rebound",
        lambda: REG.Registry(entries + [release_pin(LTS_1, "lts", None, lts_2, OCT)]))
fork = "https://releases.example.test/acme/lts/2026-10-b"
refused("a second successor of lts/2026-09: a channel never forks",
        lambda: REG.Registry(entries + [release_pin(fork, "lts", LTS_1, manifest(fork, "1.4.3", "1b" * 20, "3a" * 20), OCT)]))

print("\nSeeds, beacons, Hive indexes, and moving branches may say where to look;"
      "\nonly what a release manifest pins is part of a verified snapshot.")
