# RAR
## Agent registry structure and static publication

**Protocol identifier:** `rar/1`  
**Status:** Draft for Kody's review; not a signed registry adoption  
**Parent:** [`rapp/1`](../../../SPEC.md)  
**Related:** [`rapp-layer/1`](../../rapp-layer/1/SPEC.md)

RAR is the RAPP Agent Registry: a directory of single-file agents, stack
packs, and generated discovery files. `kody-w/RAR` is the observed instance,
not the definition of every RAR's owner or location. An agent's source file
contains its metadata; the registry is generated from those files.
Evidence: `rar-ref/build_registry.py:3-24`,
`rar-ref/build_registry.py:1522-1534`.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** have
the meanings in RAPP/1 section 2. Normative statements below describe observed
structure and checks, not new runtime powers. Evidence citations refer to the
read-only `rar-ref` checkout of `kody-w/RAR` at commit
`f8d03769202672dd8156f6e06f57e52120551e6b`. They are provenance, not files that
an implementer must fetch to understand the definitions below.

## 1. Boundary and vocabulary

The RAR registry **MUST NOT** be represented as proof of runtime or protocol
conformance. Its static agent records explicitly carry
`protocol_conformance: {profile: null, status: "not_assessed", evidence: []}`.
The RAR file has `schema: "rapp-registry/1.1"`; it is not the authenticated
estate registry (`rapp/1-registry`) defined in [RAPP/1 section 13](../../../SPEC.md#13-the-registry--an-estates-signed-root-of-trust-append-only).
Evidence: `rar-ref/scripts/build_static_api.py:263-301`,
`rar-ref/build_registry.py:1435-1467`.

The following are definitions, including the implementation terms used in
this profile. They introduce no additional RAR object types.

| Term | Definition within this repository |
|---|---|
| RAPP/1; profile; MUST, MUST NOT, REQUIRED, SHOULD, MAY | Parent protocol and subordinate specification; requirement words are defined in [RAPP/1 sections 1-2](../../../SPEC.md). |
| RAR; instance | This registry structure; an instance is one repository containing it, with its own owner and location. |
| agent; singleton; BasicAgent; perform | One Python source file containing metadata and a callable class; `BasicAgent` is the runtime base class, and `perform(**kwargs)` is the string-returning entry point. Section 3 includes a standalone example. |
| publisher; namespace; slug; name | Publisher is the account before `/` in `@publisher/slug`; namespace is that publisher's directory; slug is the final name component; name is the complete string. |
| manifest; metadata; schema | Manifest is the literal `__manifest__` dictionary embedded in source. Metadata means descriptive fields. A `schema` string identifies a file's data format; it is not a signature or a validation result. The root `manifest.json` describes static files, not an agent. |
| stack; pack; starter | Stack groups related files. A pack is a stack directory described by `pack.json`. A starter is a pack named `starter-*` or with `shelf: "starter"`; its `install.includes` selects other packs. |
| layer; part; kernel; Grail; Brainstem; shape; gate | A layer extends the unchanged Brainstem engine (Grail); a part is one pinned layer or kernel selection, a shape is their ordered desired state, and a gate records a host's check. [RAPP Layer sections 2-6](../../rapp-layer/1/SPEC.md) define execution and authority, not this discovery file. |
| egg | The carried artifact defined by [RAPP/1 section 9](../../../SPEC.md); it is not another name for `pack.json`. |
| ticket | Human/AI loading instructions, either a comment in source or the paired `index.html` and `agent.md` files. A ticket is not a receipt or permission to execute. |
| registry; catalog; projection; discovery | Registry is the generated `registry.json` index; catalog is its lean static rendering in `api/v1/catalog.json`. Projection means derived data, and discovery means finding data rather than authorizing its execution. |
| estate; frame; particle; signature; canonical | The owner's scope, immutable occurrence, payload hash, authenticated signature and canonical protocol bytes are defined in [RAPP/1 sections 4-10 and 13](../../../SPEC.md); static RAR JSON does not acquire those properties by sharing a filename. |
| receipt; notary; notarized; lifecycle; controller; tombstone | Receipt is the admission JSON in section 7. Notary is the Issue approval workflow; notarized means admitted through it. Lifecycle is the active/deleted/retired/revoked record. Controller is its numeric GitHub account identity. Tombstone is the same-path non-running retirement notice, not a missing file. |
| stub; source pointer; gated | A `.py.stub` carries metadata and a `__source__` location, not executable agent code. Gated means access to the actual source is checked separately. |
| card; swarm | Card is an agent with literal `__card__` presentation metadata. A swarm here is an existing `swarms` registry entry: a converged single-file agent or a grouping of stack agents, not a new packaging format. |
| seed; incantation; collision | Seed is the deterministic integer lookup described in section 4. Incantation is its seven-word rendering. Collision means two entries claim the same integer. Neither is a cryptographic execution authority. |
| version; semver; digest; hash; pin; SHA-256; LF; CRLF | Version is a three-integer major.minor.patch string. Digest or hash here means a SHA-256 checksum; pin means an expected exact digest. LF is byte `0a`; CRLF is bytes `0d 0a`. Section 3 defines the source-byte normalization. |
| AST; literal; compile; UTF-8; snake_case | AST is Python's abstract syntax tree; literal extraction uses `ast.literal_eval`, without executing the agent. Compile checks Python syntax without running it. UTF-8 is source/text encoding; snake_case uses underscores rather than dashes. |
| Python; SDK; Unicode; ASCII; XML | Python is the source/build language; SDK is the software development kit used by the observed builder. Unicode supplies character code points; ASCII is its basic 7-bit character set. XML is the markup syntax underlying SVG images. |
| byte-order marker; shebang; encoding header; environment variable | Optional source prefix, interpreter-selection first line, Python source-encoding comment, and a named operating-system configuration value respectively; tickets preserve the first three and list required configuration. |
| UTC; ISO timestamp; POSIX; SVG; hex; bit; bitwise OR | UTC is the time basis; ISO timestamps are textual dates/times. POSIX paths use `/`. SVG is an XML image. Hex is base-16 digest text. Bits are binary integer positions; bitwise OR combines the seed's disjoint fields. |
| JSON; object; array; null; boolean; key; field | JSON serialization of dictionaries, ordered lists, null, true/false, and named members. Python `None` serializes as JSON null. [RAPP/1 section 4](../../../SPEC.md) defines protocol canonical JSON; RAR's pretty-printed JSON is not an authoritative frame. |
| API; endpoint; GET; POST; URL; path; raw; CDN; Pages; CORS | API means the published static interface; its endpoints are files read with HTTP GET. URL is a web location and path a repository-relative filename. Raw serves repository bytes, CDN caches them, Pages serves the static site, and CORS is cross-origin read permission. POST is the HTTP method used by the separately defined [RAPP/1 wire](../../../SPEC.md). |
| Git; repository; commit; branch; main; HEAD; ledger | Git records file history in commits; a repository holds it, a branch selects its head (`HEAD` locally), and `main` is this instance's publication branch. Ledger is an append-only record, here of published paths or releases. |
| CI; workflow; Issue; PR; approval; staging; revision | CI runs automated checks; workflow is that procedure. Issue carries the submitted change; PR means pull request. Approval admits one unchanged staged candidate; revision identifies its hash-bound submission, not a moving file. |
| idempotent; atomic; provenance; authority; authentication | Idempotent means repeating unchanged inputs has the same material result. Atomic replacement prevents half-written files. Provenance records origin; authority permits an effect; authentication verifies who made a claim. |
| audience; taxonomy; match; badge; sprite | Static presentation fields: audience filters agents, taxonomy counts metadata, match ranks use cases, badge displays counts, and sprite is a generated SVG image. None changes source identity. |
| DOGG; GODD | The parent's append-only specification-revision DOGG chain is defined in [RAPP/1 section 12.2](../../../SPEC.md). GODD data means the user's retained agents and soul in [RAPP Layer section 6](../../rapp-layer/1/SPEC.md); packs do not own it. |

These definitions summarize the existing distinctions, not extra manifest
fields. Evidence: `rar-ref/template_agent.py:1-105`,
`rar-ref/build_registry.py:309-415`,
`rar-ref/build_registry.py:546-651`,
`rar-ref/scripts/build_static_api.py:263-301`,
`rar-ref/tools/build_agent_pages.py:82-143`,
`rar-ref/LAYERS.md:1-36`,
`rar-ref/scripts/apply_agent_mutation.py:422-485`.

## 2. Directory and input/output contract

The relevant layout is as follows. Braces and angle brackets below are
placeholders, not literal directory names. An implementation **MUST** keep
agent metadata in source rather than inventing a separate per-agent manifest.
It **MUST** derive registry entries from those files. Pack metadata instead
lives alongside the pack's files. Evidence:
`rar-ref/CONSTITUTION.md:18-42`,
`rar-ref/build_registry.py:39-46`,
`rar-ref/build_registry.py:608-639`.

```text
agents/@publisher/<slug>_agent.py     source, docstring and __manifest__
agents/@publisher/<slug>.py.card     optional source plus __card__
agents/@publisher/<slug>.py.stub     optional metadata plus __source__
stacks/<name>/pack.json              pack description
stacks/<name>/<file>                 files named by pack.json
swarms/@publisher/<file>.py          optional converged agents
state/agent_lifecycle.json           lifecycle input
state/receipts/<revision>.json       admission evidence
state/requests/<request>/<revision>.json  archived changes
staging/requests/<request>/<revision>/request.json  staged change metadata
staging/requests/<request>/<revision>/candidate.py  exact candidate bytes
state/published_paths.json           permanent published-path ledger
state/releases.json                 optional durable release history
state/superseded.json                optional withholding rules
cards/holo_cards.json                optional presentation input
rar.config.json                     optional instance metadata
marketplaces.json                   input for the headless static build
registry.json                       generated complete index
a/@publisher/<slug>/index.html       generated human ticket
a/@publisher/<slug>/agent.md         generated plain-text ticket
manifest.json                       generated static API descriptor
api/v1/*.json                       generated static discovery files
api/v1/audience/*.json               generated audience projections
api/v1/agent/*                       generated per-agent JSON/source copies
api/v1/sprite/*.svg                  generated images
llms.txt                            AI discovery pointers
.nojekyll                           empty static-site marker
```

The layout also has `aliases.json`, an instance administrative JSON file
with `schema`, `aliases`, and `known_mentions`. Its contents do not define
agent names, installation authority, or the registry build input. No entries
from it are reproduced by this profile. Evidence:
`rar-ref/aliases.json:1-25`,
`rar-ref/build_registry.py:940-979`,
`rar-ref/scripts/build_static_api.py:52-84`.

`llms.txt` points readers to the registry, plain-text tickets, packs, layer
guide, template, and parent protocol. It is not a second catalog.
`.nojekyll` is an empty tracked file in the observed root; it has no line
to cite. The static JSON descriptor and complete writer-owned paths are
evidenced by `rar-ref/llms.txt:1-18`,
`rar-ref/scripts/build_static_api.py:67-84`,
`rar-ref/scripts/build_static_api.py:699-795`.

The staged and archived paths above are literal builder inputs/outputs,
with the request and revision identifiers occupying their own directories.
Evidence: `rar-ref/scripts/process_issues.py:898-938`,
`rar-ref/scripts/apply_agent_mutation.py:306-311`.

## 3. Agent source and identity

A new public agent **MUST** be one Python file, conventionally
`agents/@publisher/<slug>_agent.py`, using an underscore filename.
It contains a documentation string, a literal `__manifest__`, and a
`BasicAgent` subclass whose `perform(**kwargs)` returns a string.
The callable class name is not the publisher-scoped catalog name.
Evidence: `rar-ref/template_agent.py:1-105`,
`rar-ref/CONSTITUTION.md:18-42`,
`rar-ref/build_registry.py:1025-1060`.

The literal manifest **MUST** contain these eight fields. The builder checks
their presence, a name beginning `@` and containing `/`, three dot-separated
numeric version components, and a list for `tags`. It does not impose a
closed member set or validate every value's type.
Evidence: `rar-ref/build_registry.py:72-75`,
`rar-ref/build_registry.py:86-132`.

| Field | Meaning and existing example value |
|---|---|
| `schema` | Agent format, `"rapp-agent/1.0"`. |
| `name` | Catalog identity, `"@example/hello_agent"`. |
| `version` | Source version, `"1.0.0"`. |
| `display_name` | Human label, `"Hello agent"`; spaces are allowed. |
| `description` | What it does, `"Return a greeting."`. |
| `author` | Attribution text, `"example"`. |
| `tags` | Discovery strings, `["greeting"]`. |
| `category` | Discovery category, `"general"`. |

Existing optional fields are `quality_tier` (default community in generated
views), `requires_env` (environment variable names), `dependencies`
(publisher-scoped agent names), `supersedes` (replaced agent names), and
`distinct_from` (name-to-reason mapping for deliberate similarity). The
runtime identifier **MUST** resolve statically to `[A-Za-z0-9_-]+`;
`metadata["name"]`, if resolved, **MUST** equal one of the class's resolved
runtime names. It is not required to equal `display_name`. Evidence:
`rar-ref/template_agent.py:37-105`,
`rar-ref/build_registry.py:167-268`,
`rar-ref/build_registry.py:1191-1199`,
`rar-ref/.github/workflows/build-registry.yml:84-88`.

This minimal source is an illustrative new agent, not a pre-notarized
publication. Its fallback base permits standalone use; inside a Brainstem
the existing base is imported. This follows the template rather than
requiring a separate package to inspect or test the example.
Evidence: `rar-ref/template_agent.py:78-105`.

```python
"""Return a greeting."""

__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "@example/hello_agent",
    "version": "1.0.0",
    "display_name": "Hello agent",
    "description": "Return a greeting.",
    "author": "example",
    "tags": ["greeting"],
    "category": "general",
    "quality_tier": "community",
    "requires_env": [],
    "dependencies": ["@rapp/basic_agent"],
}

try:
    from agents.basic_agent import BasicAgent
except ModuleNotFoundError:
    class BasicAgent:
        def __init__(self, name, metadata):
            self.name = name
            self.metadata = metadata

class HelloAgent(BasicAgent):
    def __init__(self):
        super().__init__("HelloAgent", {
            "name": "HelloAgent",
            "description": __manifest__["description"],
            "parameters": {"type": "object", "properties": {}},
        })

    def perform(self, **kwargs):
        return "Hello."
```

Source extraction **MUST NOT** import or execute the agent: read UTF-8,
`ast.parse`, compile without execution, and `ast.literal_eval` the
`__manifest__` assignment. Source identity `_sha256` **MUST** be lowercase
SHA-256 of the entire file after replacing CRLF by LF, with no other
normalization. A previous equal `(name, version, _file)` with a different
digest is rejected; the precise comment-only loading-ticket exception
requires removing the expected ticket to recover the previous digest, and
still requires fresh matching lifecycle evidence.
Evidence: `rar-ref/build_registry.py:86-109`,
`rar-ref/build_registry.py:481-493`,
`rar-ref/build_registry.py:686-714`.

The `_install_filename` projection is calculated by removing leading `@`
from the name, replacing each run outside `[A-Za-z0-9_]` by `_`, trimming
outer underscores, lowercasing, appending `_agent` unless already present,
then adding prefix `rar_` and suffix `.py`.
Evidence: `rar-ref/build_registry.py:78-83`.

The builder recognizes `.py.card` and prefers it to `.py` for the same
manifest name. A `.py.stub` **MUST** contain only an optional first docstring
and single-target assignments to `__manifest__` and `__source__`. The
source pointer has `schema: "rapp-source/1.0"`, `type` either
`github_private` or `github_public`, `repo` in owner/name form, and `path`.
Its registry entry has `type: "stub"`, forced `quality_tier: "private"`,
`_source`, and `_stub_sha256` of the stub itself, not the inaccessible
source. A plain-text ticket **MUST NOT** describe that stub as executable
agent code. Evidence: `rar-ref/build_registry.py:328-415`,
`rar-ref/build_registry.py:1064-1073`,
`rar-ref/build_registry.py:1231-1316`,
`rar-ref/tools/build_agent_pages.py:96-117`.

## 4. Registry build

`python3 build_registry.py` is the registry operation. It reads the source
tree plus the available state/presentation inputs; it is not literally a
one-file-input build. It **MUST** scan sorted `.py` and `.py.card` paths,
exclude utility/template/component-source files and `RAR_TOMBSTONE` notices,
validate manifests and statically resolved runtime identifiers, and prefer
the card form for duplicate names. Existing nested paths ending in
`<vertical>_stacks/<name>_stack/` derive `_stack` and `_stack_vertical`.
Evidence: `rar-ref/build_registry.py:465-478`,
`rar-ref/build_registry.py:934-1073`.

The source checks reject matches for `os.system(...)`, suspicious `open(...)`
paths, and possible literal credentials. Dynamic `exec`, `eval`, dynamic
import, and compile-to-exec are instead tagged in sorted `_capabilities`;
`_uses_exec` is true for `exec` or `compile_exec`. The dangerous-pattern
allowlist is empty. Duplicate display labels and seed collisions block a
successful build. These checks are not a proof of safe execution.
Evidence: `rar-ref/build_registry.py:418-463`,
`rar-ref/build_registry.py:1078-1092`,
`rar-ref/build_registry.py:1327-1364`,
`rar-ref/build_registry.py:1549-1563`.

For each agent the builder copies the manifest, then derives these fields:
`_file` (POSIX relative path), `_install_filename`, `_sha256`, `_seed`,
`_size_kb` (normalized byte length / 1024, rounded to one decimal),
`_lines` (number of newline-separated text pieces, including a final empty
piece), `_has_card`, `_added_at`, `_first_commit_sha`,
`_latest_commit_sha`, and optional `_card` and `_card_sha256`.
Git fields come from available history, not an invented publication date;
they are null if that history is unavailable. `_has_card` recognizes the
card source or matching presentation metadata (also checking dash/underscore
name variants). `_card_sha256` is the full SHA-256 of UTF-8
`json.dumps(card, sort_keys=True, separators=(",", ":"))`, with Python's
default ASCII escaping, not the agent source checksum. Lifecycle fields
are described in section 7.
Evidence: `rar-ref/build_registry.py:730-804`,
`rar-ref/build_registry.py:50-70`,
`rar-ref/build_registry.py:1103-1140`.

`_seed` is computed from `(name, category, quality_tier, tags, dependencies)`,
using defaults `general`, `community`, `[]`, `[]` for the last four inputs.
It is a metadata lookup, not the file digest. Previous `_seed` values and
distinct previous `_seed_aliases` are retained in `_seed_aliases`, excluding
the current seed. Pack seeds use `@stacks/<name>`, `pipeline`, `community`,
the first 31 capabilities, and sorted listed `_agent.py` filenames.
Evidence: `rar-ref/build_registry.py:534-543`,
`rar-ref/build_registry.py:644-673`,
`rar-ref/build_registry.py:1109-1115`,
`rar-ref/build_registry.py:1318-1352`.

For an independent implementation, the integer calculation is fully
specified here. Let `h(s)` start at zero and, for each Unicode character,
set `h = (31*h + ord(character)) & 0xffffffff`. The ordered category list is
`core, devtools, pipeline, integrations, productivity, general,
federal_government, slg_government, it_management, manufacturing, energy,
retail_cpg, healthcare, human_resources, financial_services, b2b_sales,
b2c_sales, professional_services, software_digital_products`.
The corresponding primary types are
`LOGIC, LOGIC, DATA, DATA, SOCIAL, SOCIAL, SHIELD, SHIELD, SHIELD,
CRAFT, CRAFT, CRAFT, HEAL, HEAL, WEALTH, WEALTH, WEALTH, WEALTH, DATA`.
Extended categories are `analysis, creative, meta, platform, workflow`,
with types `LOGIC, SOCIAL, LOGIC, DATA, DATA`. An unknown category uses the
`general` index and primary type `SOCIAL`. Evidence:
`rar-ref/build_registry.py:527-531`,
`rar-ref/rapp_sdk.py:684-731`,
`rar-ref/rapp_sdk.py:1040-1113`.

Search the following types in order, skipping the primary type. The first
whose keyword occurs as a substring in lowercased tags joined with spaces
is the secondary type; absent a match its index is 7. Type indices are
`LOGIC=0, DATA=1, SOCIAL=2, SHIELD=3, CRAFT=4, HEAL=5, WEALTH=6`.
Evidence: `rar-ref/rapp_sdk.py:733-741`,
`rar-ref/rapp_sdk.py:777-792`.

| Type | Keywords |
|---|---|
| LOGIC | ai, ml, algorithm, compute, analysis, ast, parse, model, intelligence |
| DATA | data, pipeline, etl, sync, migration, import, export, extract, transform |
| SOCIAL | email, chat, meeting, communication, demo, presentation, coach, assistant |
| SHIELD | compliance, security, audit, governance, risk, regulatory, permit, license |
| CRAFT | inventory, supply, maintenance, production, manufacturing, field, dispatch |
| HEAL | patient, clinical, care, health, wellness, staff, credentialing, intake |
| WEALTH | sales, revenue, pricing, deal, proposal, billing, financial, portfolio |

The seed is the bitwise OR of: `h(name)<<32`, category index `<<27`,
secondary index `<<24`, tier index `<<22`, `min(31,len(tags))<<17`,
`min(15,len(dependencies))<<13`, and `h(" ".join(tags)) & 0x1fff`
(zero for empty tags). Tier indices are experimental 0, community 1,
verified 2, official 3; frontier uses 0 and also sets bit 64; other tiers
use 1. Extended categories also set bit 65 and use their extended-list
index in the category field. These integers can exceed JSON's interoperable
exact integer range; they are existing catalog values, not newly defined
RAPP/1 payload integers. Evidence: `rar-ref/rapp_sdk.py:1040-1113`.

The seven-word encoding takes indices `(seed >> (10*i)) & 1023` for
`i = 0..6`, **least significant first**, and joins the indexed uppercase
words with spaces. Decoding uppercases input, treats hyphens as spaces,
requires seven known words, and ORs their indices shifted by `10*i`.
The observed 1,024-entry ordered table follows, so an implementer need
not invent words or fetch the SDK. Line breaks are only whitespace.
Evidence: `rar-ref/rapp_sdk.py:644-677`.

```text
FORGE ANVIL BLADE RUNE SHARD SMELT TEMPER WELD CHISEL BRAND MOLD CAST STAMP
ETCH CARVE BIND FUSE ALLOY INGOT RIVET CLASP THORN BARB SPIKE PRONG EDGE HONE
GRIND QUENCH SEAR HAMMER STOKE FIRE FROST STORM TIDE QUAKE GUST BOLT SURGE
BLAZE EMBER PYRE ASH SMOKE SPARK FLARE FLASH FLOOD GALE DRIFT MIST HAZE VOID
FLUX PULSE WAVE SHOCK BURST CRACK ROAR HOWL ECHO BOOM THUNDER VENOM BLIGHT
SCORCH SINGE CHAR WITHER ERODE CORRODE DISSOLVE OAK PINE MOSS FERN ROOT VINE
BLOOM SEED GROVE GLEN VALE CRAG PEAK RIDGE GORGE CLIFF SHORE REEF DUNE MARSH
CAVE LAIR DEN NEST HIVE BURROW STONE IRON STEEL GOLD JADE ONYX RUBY OPAL AMBER
PEARL CORAL QUARTZ OBSIDIAN FLINT GRANITE BASALT COBALT CHROME BRONZE COPPER
NICKEL RELIC TOTEM SIGIL GLYPH WARD CHARM BANE DOOM FATE OMEN ORACLE SAGE SEER
MAGE DRUID SHAMAN WRAITH SHADE PHANTOM SPECTER GOLEM TITAN DRAKE WYRM GRYPHON
SPHINX HYDRA CHIMERA SCROLL TOME CODEX LORE MYTH FABLE SAGA EPIC VERSE CHANT
HYMN DIRGE OATH CREED VOW AURA MANA ETHER PRISM NEXUS VORTEX RIFT WARP BREACH
PORTAL GATE VAULT SHRINE ALTAR CRYPT SPIRE STRIKE SLASH THRUST PARRY GUARD
SHIELD HELM LANCE MACE PIKE STAFF WAND DAGGER BOW ARROW QUIVER ARMOR PLATE
GAUNTLET VISOR CLOAK CAPE MANTLE AEGIS BULWARK RAMPART BASTION CITADEL KEEP
TOWER FORT RALLY CHARGE SIEGE FLANK AMBUSH ROUT VALOR MIGHT FURY WRATH RAGE
SPITE MALICE GRUDGE HAVOC CHAOS DASH LEAP SPRINT LUNGE DIVE SOAR GLIDE PROWL
STALK CREEP SWIFT FLEET BRISK RAPID SPIN WHIRL TWIST COIL SPIRAL ORBIT ARC
CURVE BEND LOOP DAWN DUSK NOON NIGHT SHADOW GLEAM GLOW SHINE BEAM RAY HALO
LUSTER MURK GLOOM DREAD FELL GRIM STARK BLEAK PALE ASHEN DIRE GRAVE SOMBER
EBON ABYSS SHRIEK WAIL RUMBLE HISS GROWL SNARL BARK BELLOW DRONE CHIME TOLL
KNELL CLANG CLASH SNAP THUD RING PEAL GONG HORN DRUM FLUTE LYRE PIPE BOLD KEEN
FIERCE STERN VAST DEEP GRAND PRIME NOBLE ROYAL SACRED ANCIENT PRIMAL ELDER
PURE VIVID SHARP BRIGHT DARK WILD CALM STILL SILENT STRONG PROUD BRAVE WISE
JUST RAW DENSE SOLID WHOLE CORE APEX ZENITH NADIR CUSP BRINK VERGE CREST STAR
MOON SUN COMET NOVA SOLAR LUNAR ASTRAL COSMIC NEBULA QUASAR PULSAR ECLIPSE
AURORA CORONA PHASE WANE WAX WOLF HAWK EAGLE RAVEN SERPENT VIPER COBRA FALCON
STAG BEAR LION TIGER LYNX PANTHER CONDOR OSPREY CRANE HERON OWL CROW BULL BOAR
RAM HORSE MARE STALLION AX ORB AWE OAT EEL URN ELK ELM ION IRE ORE AIM ZAP JAB
JAW JET JOT JAG HEX HEW HUE HUM DIN DUB DYE FIN FIG FOG FUR GAP GEM GNU SOUL
MIND WILL FORCE POWER CRAFT SKILL GRACE POISE NERVE GRIT METTLE VIGOR ZEAL
VERVE PLUCK GUILE CUNNING WILE LURE TRAP SNARE BAIT DECOY RUSE FEINT GAMBIT
PLOY MESA TARN FORD PASS BLUFF KNOLL MOOR HEATH STEPPE TUNDRA DELTA BASIN
PLATEAU FJORD ISLE ATOLL STRAIT CHANNEL HARBOR COVE BAY GULF SOUND CREEK BROOK
RAPIDS FALLS CASCADE ARCH DOME PILLAR COLUMN BRIDGE WALL MOAT RAMP LEDGE STEP
STAIR HALL NAVE ALCOVE NICHE SILL TRUSS BRACE STRUT JOIST FRAME PLINTH DAIS
THRONE QUEST HUNT TRIAL ORDEAL RITE RITUAL PACT BOND PLEDGE DECREE EDICT
MANDATE LAW RULE REIGN CROWN SCEPTER BANNER EMBLEM BADGE MARK SEAL TOKEN GUILD
CLAN TRIBE ORDER SECT COVEN LEGION HORDE SWARM PACK FLOCK BROOD CLUTCH CRUX
JINX GLINT DINT STINT KNIT SLIT SPLIT WHIT CLEFT DEFT HEFT LEFT THEFT WEFT
BEREFT SHAFT GRAFT RAFT DRAFT TUFT LOFT CROFT DROIT BRUNT BLUNT STUNT RUNT
GRUNT FRONT FONT HAUNT GAUNT FLAUNT JAUNT TAUNT SALT MALT HALT JOLT COLT MOLT
SMOLT QUALM BALM PSALM FARM HARM ALARM DISARM FOREARM PLUME FUME LOOM ZOOM
GROOM BROOM VROOM SCARCE TERSE MORSE COURSE SOURCE NORSE REMORSE WRENCH CLENCH
STENCH TRENCH DRENCH FRENCH BENCH TORCH PORCH MARCH LARCH STARCH SEARCH PERCH
BIRCH CHURCH THATCH CATCH MATCH BATCH HATCH LATCH PATCH WATCH SCRATCH SNATCH
HEDGE WEDGE DREDGE SLEDGE FRIDGE DANCE TRANCE GLANCE STANCE PRANCE CHANCE
ADVANCE ENHANCE BLISS MISS KISS DISMISS AMISS REMISS WHISK DISK RISK FRISK
TUSK MUSK RUSK HUSK CROAK SOAK STROKE SPOKE BROKE WOKE INVOKE EVOKE PROVOKE
VEIN CHAIN PLAIN STRAIN GRAIN TRAIN BRAIN DOMAIN TERRAIN REMAIN TREAD SPREAD
THREAD SHRED BRED SLED STEAD INSTEAD COST LOST HOST GHOST MOST POST ROAST
TOAST COAST BOAST STREAM DREAM TEAM CREAM SCHEME THEME SUPREME EXTREME SWAY
FRAY PRAY STRAY ARRAY DECAY RELAY CONVEY OBEY SURVEY BETRAY THROW FLOW SNOW
GROW KNOW BELOW HOLLOW CLIMB RHYME SLIME THYME SUBLIME PARADIGM PROWESS DURESS
FORTRESS MISTRESS COMPASS BYPASS SURPASS AMASS CRIMSON LINDEN MAIDEN WARDEN
GOLDEN MOLTEN FROZEN CHOSEN WOVEN SCYTHE CRUCIBLE TORRENT TEMPEST MAELSTROM
CINDER INFERNO TYPHOON CYCLONE GLACIER ICECAP PERMAFROST MONSOON SOLSTICE
EQUINOX MERIDIAN TWILIGHT MIDNIGHT DAYBREAK SENTINEL WATCHER HUNTER RANGER
SCOUT TRACKER SEEKER FINDER KEEPER BINDER ARBITER HERALD ENVOY REGENT PREFECT
CONSUL MARSHAL VASSAL SQUIRE KNIGHT PALADIN CHAMPION PARAGON MONARCH SOVEREIGN
OVERLORD WARLORD CHIEFTAIN PATRIARCH MATRIARCH PROPHET MYSTIC HERMIT ASCETIC
NOMAD PILGRIM WANDERER EXILE OUTCAST ROGUE REBEL VAGRANT DRIFTER MARAUDER
BRIGAND CORSAIR BUCCANEER RAIDER REAVER SLAYER BERSERKER GLADIATOR CENTURION
LEGIONNAIRE TEMPLAR CRUSADER INQUISITOR ZEALOT HARBINGER AUGUR PORTENT PRESAGE
AUGURY PROPHECY DIVINATION REVELATION EPIPHANY REMNANT VESTIGE ARTIFACT
FRAGMENT SPLINTER SLIVER MORSEL CRUMB PARTICLE MOTE FILAMENT STRAND FIBER
SINEW TENDON LIGAMENT MARROW ICHOR ELIXIR POTION TONIC SALVE REMEDY ANTIDOTE
CURE PANACEA CATALYST REAGENT COMPOUND TINCTURE DISTILL INFUSE IMBUE ENCHANT
CONJURE SUMMON BANISH DISPEL REVOKE ANNUL NEGATE NULLIFY SUNDER CLEAVE REND
SHATTER FRACTURE RUPTURE PIERCE IMPALE SKEWER GORE MAIM RAVAGE DEVASTATE
OBLITERATE ANNIHILATE ERADICATE PURGE EXPUNGE EFFACE EXTINGUISH QUELL SUBDUE
VANQUISH CONQUER PREVAIL TRIUMPH ASCEND TRANSCEND EVOLVE AWAKEN ARISE EMERGE
MANIFEST EMBODY HARNESS WIELD MASTER COMMAND PROCLAIM SANCTIFY CONSECRATE
ANOINT BESTOW ENDOW BEQUEST LEGACY HEIRLOOM COVENANT COMPACT TREATY ACCORD
ALLIANCE FEDERATION DOMINION REALM KINGDOM EMPIRE DYNASTY EPOCH AEON CYCLE
HELIX MATRIX LATTICE TAPESTRY MOSAIC CIPHER ENIGMA RIDDLE PUZZLE LABYRINTH
MAZE CAULDRON CHALICE GOBLET GRAIL TRIDENT MAUL FLAIL HALBERD GLAIVE RAPIER
SABRE KATANA MACHETE SCIMITAR CUTLASS BROADSWORD GREATSWORD LONGBOW CROSSBOW
BALLISTA CATAPULT TREBUCHET MIRAGE ILLUSION REVENANT LICH BANSHEE GHOUL
VAMPIRE WEREWOLF GARGOYLE BASILISK KRAKEN LEVIATHAN BEHEMOTH COLOSSUS
JUGGERNAUT MONOLITH OBELISK ZIGGURAT MINARET PAGODA DOLMEN BARROW CATACOMB
DUNGEON PARAPET TURRET BATTLEMENT DRAWBRIDGE PORTCULLIS BARBICAN PALISADE
CONDUIT PYLON TORQUE RATCHET LODESTONE KEYSTONE CAPSTONE BEDROCK SEQUOIA
REDWOOD CYPRESS HEMLOCK WILLOW ASPEN HICKORY JUNIPER MAGNOLIA HAWTHORN SAFFRON
MYRRH MANGROVE ORCHID THISTLE POPPY HEATHER JASMINE VECTOR SCALAR TENSOR
FULCRUM PIVOT CRESCENT PINNACLE VERTEX
```

The root JSON has this structure; field names and format identifiers are
literal. Counts and contents are derived, not fixed to this instance's size.
`stats` holds `total_agents`, `total_swarms`, `total_stubs`, publisher and
category counts, and sorted `publisher_list` and `category_list`.
`duplicates` contains `{display_name, agents}` for conflicting labels.
`lifecycle` holds its `schema`, `receipt_schema`, and `tombstones`.
`superseded` holds its `schema`, `withheld_count`, `rules`, and explanatory
`note`. Optional `stacks`, `stack_packs`, `releases`, `latest_release`,
and `instance` are added only when their inputs produce them.
Evidence: `rar-ref/build_registry.py:1435-1534`.

```json
{
  "schema": "rapp-registry/1.1",
  "version": "1.1.0",
  "generated_at": "<current UTC ISO timestamp>",
  "stats": {
    "total_agents": 0, "total_swarms": 0, "total_stubs": 0,
    "publishers": 0, "categories": 0,
    "publisher_list": [], "category_list": []
  },
  "duplicates": [],
  "agents": [],
  "swarms": [],
  "lifecycle": {
    "schema": "rar-agent-lifecycle/1.0",
    "receipt_schema": "rar-receipt/1.0", "tombstones": []
  },
  "superseded": {
    "schema": "rar-superseded/1", "withheld_count": 0, "rules": [],
    "note": "withheld agents remain at their published paths; they are omitted from every lookup"
  }
}
```

The example shows the empty root shape; populate `agents` and recompute
counts and lists after adding the example source. `swarms` combines converged
entries and stack groupings. Converged files carry `__swarm__` with required
`schema, id, display_name, summary, category, publisher, produced_by`;
schema is `rapp-swarm/1.0` and `produced_by` includes `method`. Stack
groupings carry `type: "stack"`, member names and file paths.
Evidence: `rar-ref/build_registry.py:309-325`,
`rar-ref/build_registry.py:1142-1230`,
`rar-ref/build_registry.py:1366-1410`.

The builder **MUST** apply `state/superseded.json` rules before publication:
withheld agents remain on disk but leave lookup arrays; groupings with
withheld members are removed, and the stack index is trimmed. Malformed
withholding JSON is an error. Release history is projected from
`state/releases.json`; `latest_release` selects the last non-canary record,
or the last record if all are canaries. Optional `rar.config.json`
projects `instance: {role, owner, repo, upstream}`. Evidence:
`rar-ref/build_registry.py:921-931`,
`rar-ref/build_registry.py:1412-1467`,
`rar-ref/build_registry.py:1489-1534`.

Writing uses an indented temporary JSON file followed by atomic replacement.
Agent validation errors can leave a newly written partial registry on disk
even though the command returns 1; success **MUST** be determined by exit
status, not file existence. Pack lifecycle errors return 1 before that
write. Ticket pages are generated only after other build errors are absent.
Evidence: `rar-ref/build_registry.py:1476-1483`,
`rar-ref/build_registry.py:1536-1570`.

## 5. Packs, layers and retirement

A pack is read from `stacks/<name>/pack.json`. Existing examples use
`schema: "rapp-rar-stack/1.2"`, `name`, `display_name`, `version`,
`purpose`, `install`, and `files`. `install` describes selection and
placement; its observed forms include `type: "packs"` with `includes`,
and `type: "agent_pack"` with `agents`, `pages`, `destination`, and
`includes`. `one_liner` is human installation text, not an extra endpoint.
Each `files` entry maps a relative filename to `{size, sha256}`, where size
is the byte length and sha256 pins the raw file bytes. A new pack can be
built by writing its files first, calculating those sizes/digests, then
writing this description. Evidence:
`rar-ref/stacks/starter-personal/pack.json:1-26`,
`rar-ref/stacks/ticket-page/pack.json:1-29`,
`rar-ref/tools/sync_layers.py:268-277`.

The pack projection **MUST NOT** change the pack's source files. It contains
`name, display_name, version, schema, status, path, purpose, files,
_verified, shelf`, plus optional `retired`, object-valued `kernel`,
`_seed`, and `_incantation`. Purpose is truncated to 300 characters.
Projection defaults are directory name, that name for display, version
`0.0.0`, schema `rapp-rar-stack/1.0`, and status `current`.
Projected `files` entries are `{sha256, verified}`, not the original size
records. A pack's `_verified` is true only for a nonempty file mapping with
every file present and matching its **raw-byte** SHA-256. A mismatch is
published as unverified, not repaired or made a registry-build error.
Summon clients **MUST** refuse unverified packs. Evidence:
`rar-ref/build_registry.py:594-651`,
`rar-ref/build_registry.py:1471-1485`.

Shelf is `starter` for starter selection, otherwise `app` for
`kind_label: "rapplication"`, otherwise `pack`. A pack seed colliding with
an agent seed, retained agent seed, or earlier pack seed is withheld rather
than reused. `_incantation` renders a seed using section 4's seven-word
encoding and table.
Evidence: `rar-ref/build_registry.py:640-650`,
`rar-ref/build_registry.py:1476-1479`,
`rar-ref/rapp_sdk.py:644-663`.

Pack status **MUST** be `current` (also the absent-field default) or
`retired`. A current pack **MUST NOT** carry `retired`. A retired pack
**MUST** carry `retired: {since, reason, replacement}`: `since` is a real
calendar date in `YYYY-MM-DD`, `reason` is nonempty text after trimming,
and `replacement` is a present field containing either a nonempty name or
null. The builder does not check that a replacement name resolves.
Retirement passes through unchanged and does not alter digest verification
or the seed calculation. Evidence: `rar-ref/build_registry.py:546-572`,
`rar-ref/build_registry.py:594-601`,
`rar-ref/build_registry.py:636-650`.

A starter's transitive `install.includes` **MUST NOT** reach a retired pack.
Includes encountered in that walk **MUST** be a list of strings. The walk
avoids revisiting cycles and stops at names absent from the known packs;
it does not reject unknown names or cycles generally. Retired entries
remain in `stack_packs` and in the lean static catalog. Evidence:
`rar-ref/build_registry.py:574-591`,
`rar-ref/scripts/build_static_api.py:576-591`.

For packs with `install.parts`, `tools/sync_layers.py` derives facts before
registry publication: layer docstring and synchronous `apply()`,
literal `PROVEN_GRAIL` (tested engine file digests), `TOUCHES` (exclusive
hooks), and `WRAPS` (composable hooks). Part identifiers, files, kinds,
points, locators, and optional `install.seed` select existing parts;
`install.seed` here is a **list of part ids**, not the integer `_seed`.
The synchronizer stamps comment-only tickets, hashes final bytes, refreshes
`sha256, proven_grail, touches, wraps, what`, file sizes and digests, and
generates the two ticket files. Agent/part page collisions are rejected.
`kernel.proven` is the intersection of selected layer proof sets; a
`kind: "kernel"` part is not assumed to be an `apply()` layer. These
catalog facts do not override the layer profile's runtime checks.
Evidence: `rar-ref/LAYERS.md:11-36`,
`rar-ref/LAYERS.md:80-106`,
`rar-ref/tools/sync_layers.py:209-277`.

## 6. Tickets and static discovery

Each indexed agent has `a/<name>/index.html` and `a/<name>/agent.md`; the
literal leading `@` stays in the publisher directory. The page exposes the
human label, description, raw file, browse link, and plain-text counterpart.
The Markdown explains loading, dependencies, required environment variables,
and trust caution; stubs instead explain separately authenticated access.
Unchanged page contents are not rewritten. Ticket path validation rejects
absolute paths, `..`, non-agent roots, and identities outside
`@[A-Za-z0-9_-]+/[A-Za-z0-9_-]+`. Evidence:
`rar-ref/tools/stamp_ticket.py:29-45`,
`rar-ref/tools/build_agent_pages.py:82-143`,
`rar-ref/tools/build_agent_pages.py:137-231`.

Comment tickets preserve byte-order marker, shebang, and Python encoding
header, and **MUST NOT** change the AST. Ticket checking and stamping
operate only on the registry's listed canonical files, not an independent
scan. Stamping changes source bytes, so it is followed by matching admission
evidence and a registry rebuild. Evidence:
`rar-ref/tools/stamp_ticket.py:2-7`,
`rar-ref/tools/stamp_ticket.py:61-97`,
`rar-ref/tools/stamp_ticket.py:100-124`.

The published API consists of files, not a running registry service. There
are two existing builders with distinct ownership. The headless builder
**MUST NOT** overwrite `api/v1/index.json`. It reads `registry.json`,
requires nonempty agents and valid
`marketplaces.json` (`schema: "rapp-marketplaces/1.0"`, list `marketplaces`),
and reads the existing skills projection if present. Its `--check` option
computes outputs without writing; it does **not** compare generated
contents with committed files. Evidence:
`rar-ref/scripts/build_static_api.py:5-21`,
`rar-ref/scripts/build_static_api.py:52-84`,
`rar-ref/scripts/build_static_api.py:488-546`.

| File | Existing shape and role |
|---|---|
| `manifest.json` | `rapp-static-api/1.0`; fields `name, title, description, raw_base, cdn_base, pages_base, generated, cors, auth, stability, endpoints, recipes`. Endpoints map names to static URLs/descriptions. |
| `api/v1/catalog.json` | `rar-catalog/1.0`; `description, generated, count, self_url, agents, stack_packs`. Agents sorted by namespaced name; packs pass through, including retired ones. |
| `api/v1/taxonomy.json` | `rar-taxonomy/1.0`; `generated`, category/publisher/quality-tier/tag arrays of `{name, count}`. |
| `api/v1/audience/business.json`, `consumer.json` | `rar-catalog/1.0`; `audience, description, generated, count, self_url, agents`; each includes its own audience and `both`. |
| `api/v1/audience/map.json` | `rar-audience-map/1.0`; description, generated time, legend, counts, self URL, per-name `map` (`b/c/x`) and numeric `scores` (`b/c`). |
| `api/v1/match.json` | `rar-match/1.0`; `description, generated, how_to_query, use_cases, index`. The query instructions explain summing term weights per agent id. |
| `api/v1/marketplaces.json` | Marketplace input plus `self_url, source_url, count`. |
| `api/v1/status.json` | `rar-static-api-status/1.0`; `generated, summary, endpoints`, with endpoint name, count and `sha8`. |
| `api/v1/badge.json` | `schemaVersion: 1`, label, message and color for a counts badge. |
| `api/v1/index.json` | `rar-pokedex-api/1.0`; name, description, version, generated time, count, self URL and per-agent references. |
| `api/v1/agent/<id>.json`, `.py`, optional `.card` | `rar-pokedex-agent/1.0` metadata and source mirrors; id removes leading `@`, replaces `/` by `__` and `.` by `_`. |
| `api/v1/sprite/<id>.svg` | Deterministic generated image linked from the per-agent JSON. |

These are existing paths and fields, not proposed endpoints. Evidence:
`rar-ref/scripts/build_static_api.py:258-301`,
`rar-ref/scripts/build_static_api.py:459-476`,
`rar-ref/scripts/build_static_api.py:568-699`,
`rar-ref/scripts/build_static_api.py:699-847`,
`rar-ref/scripts/build_pokedex_api.py:47-61`,
`rar-ref/scripts/build_pokedex_api.py:157-198`,
`rar-ref/scripts/build_pokedex_api.py:282-353`.

The lean agent record carries `artifact_type: "agent"`,
`protocol_conformance` as in section 1, `id, name, display_name,
description, version, publisher, author, category, tags, quality_tier,
audience, requires_env, dependencies`, then
`source: {path, raw, cdn, sha256}` and
`stats: {lines, size_kb, added_at}`. Here id removes `@` and replaces `/`
by `__` (unlike the per-agent API it does not replace dots).
`source.sha256` currently reads `_sha256` only: a stub's
`_stub_sha256` is not substituted by this builder. Consumers cannot infer
that a missing digest proves private source integrity.
Evidence: `rar-ref/scripts/build_static_api.py:258-301`.

`sha8` is the **first 12** lowercase hex characters of SHA-256 over UTF-8
`json.dumps(payload, sort_keys=True, separators=(",", ":"))`, despite the
field's name. It is change-detection metadata, not a full source pin.
Audience selection and use-case ranking derive from metadata, not execution
proof. Evidence: `rar-ref/scripts/build_static_api.py:200-255`,
`rar-ref/scripts/build_static_api.py:380-476`,
`rar-ref/scripts/build_static_api.py:479-485`.

## 7. Admission, receipts and published paths

The staged change uses `schema: "rar-change-request/1.0"`. Its
`revision_id` is the full lowercase SHA-256 of UTF-8 JSON with sorted
keys, separators `(",", ":")`, and `ensure_ascii=True`, over **only**
the following basis keys, taking `""` for any missing key:

```text
schema request_id client_request_id idempotency_key client_command_sha256
action agent actor_id source_body_sha256 candidate_sha256 candidate_version
candidate_quality_tier source_url base_sha256 base_version base_quality_tier
base_lifecycle_sha256 base_lifecycle_version base_lifecycle_receipt reason
publisher slug canonical_path
```

`actor_id` is the numeric submitter identity; `source_body_sha256` pins the
Issue body; `source_url` records its source locator; `reason` is explanatory
text. The `candidate_*` fields pin proposed bytes/version/tier; `base_*`
pin the existing file and lifecycle preconditions. `client_request_id`,
`idempotency_key`, and `client_command_sha256` retain caller identity and
duplicate-command evidence. The staged record adds `revision_id`,
`status: "pending_review"`, Issue number/node id, `repository_id`,
`actor_login`, `issue_updated_at` and `created_at`; those additions are
not in the revision-hash basis. Evidence:
`rar-ref/scripts/process_issues.py:171-213`,
`rar-ref/scripts/process_issues.py:898-938`.

Application **MUST** validate the revision hash and directory identifiers.
The agent identity matches `@([^/]+)/([a-z0-9_]+)`; the file slug appends
`_agent` if needed. Create paths **MUST** be
`agents/<publisher>/<file_slug>.py`. Canonical paths **MUST** remain in
the publisher's `agents/` namespace and resolve within `agents/`.
For create/update/restore the staged `candidate.py` **MUST** match the
recorded digest, manifest name, version and tier. Delete **MUST NOT**
carry candidate bytes. A pending Issue selects exactly one staged record
matching its Issue number, numeric author id and body hash; an already
applied archived record is used only for validated repeat application.
Evidence: `rar-ref/scripts/apply_agent_mutation.py:48-194`.

The registry builder accepts an agent absent from lifecycle input as
`_lifecycle: "legacy_active"`. This is not a notarization. Once an active
lifecycle record exists, file version, digest and canonical path **MUST**
match it. `latest_receipt` **MUST** begin `rar_` and resolve to
`state/receipts/<suffix>.json`. Schema, id, agent, version, canonical path,
quality tier, numeric controller identity, notarized status and artifact
digest **MUST** match. Success adds `_lifecycle: "notarized"`, `_receipt`,
`_controller: {github_id, github_login}` and `_provenance` with
`issue, submitted_by, accepted_by, checks`. Evidence:
`rar-ref/build_registry.py:807-874`.

An active file with lifecycle `deleted`, `retired`, or `revoked` is an
error. Lifecycle tombstones for these statuses **MUST** have matching
receipts, including actions `agent.delete`, `agent.retire`, and
`agent.revoke` respectively. The tombstone source notice itself is skipped
by the agent scan. Evidence: `rar-ref/build_registry.py:819-836`,
`rar-ref/build_registry.py:877-915`,
`rar-ref/build_registry.py:934-938`,
`rar-ref/build_registry.py:1001-1004`.

An Issue approval workflow **MUST** check maintain/admin permission,
open Issue state, `approved` and `agent-submission` labels, and unchanged
Issue body since approval; it rechecks the body before commit. Admission
applies exactly staged bytes, runs security, registry, card, URL, static
builds and tests, then commits and publishes. A receipt written locally
before those checks finish is not evidence that publication succeeded.
Evidence: `rar-ref/.github/workflows/approve-agent.yml:15-35`,
`rar-ref/.github/workflows/approve-agent.yml:51-145`,
`rar-ref/.github/workflows/approve-agent.yml:146-180`.

Application **MUST** reject a changed source-base digest or changed staged
lifecycle evidence. Create requires an unused identity; update requires a
higher numeric version; restore requires a deleted/retired identity and a
version higher than the tombstone's. Delete writes a notice at the same
path and records the **previous agent's** digest in its receipt, not the
notice's digest. Reapplication validates the existing receipt and its
projection instead of admitting the bytes twice.
Evidence: `rar-ref/scripts/apply_agent_mutation.py:278-414`.

A receipt has these existing fields; they are admission evidence within
the repository, not a new signed RAPP/1 frame. `revision_id` identifies the
hash-bound staged change; `request_id` groups its revisions. The receipt id
is `rar_<revision_id>`, filename `<revision_id>.json`.
Evidence: `rar-ref/scripts/apply_agent_mutation.py:278-311`,
`rar-ref/scripts/apply_agent_mutation.py:422-485`.

| Receipt field | Meaning |
|---|---|
| `schema, id, issuer` | `rar-receipt/1.0`, receipt id, admitting repository identity. |
| `request_id, revision_id, action, agent, canonical_path` | Exact submission, operation and named source location. |
| `version, quality_tier` | Admitted source version and tier. |
| `controller` | `github_id, github_login` of the retained owner. |
| `artifact` | `algorithm: "sha256-lf-v1", digest`; the normalized source checksum. |
| `previous` | Prior `version, digest, receipt` linking admission history. |
| `submission` | Submitter `github_id, github_login, issue_number, issue_node_id, source_body_sha256`. |
| `acceptance` | Approver `github_id, github_login, workflow_run, checks, policy`; policy is `rar-notary/1.0`. |
| `status, created_at` | `notarized` or `deleted`, and creation time. |

The lifecycle input uses `schema: "rar-agent-lifecycle/1.0"` and an `agents`
object keyed by namespaced name. Its records contain
`status, version, quality_tier, owner_github_id, owner_github_login,
canonical_path, sha256, latest_receipt, updated_at`. The active status is
`active`, although the matching receipt says `notarized`. No JSON signature
is produced by this receipt construction.
Evidence: `rar-ref/build_registry.py:962-979`,
`rar-ref/scripts/apply_agent_mutation.py:422-485`.

Trusted PR policy checks out the validator from the base commit and the
candidate separately without executing it. Canonical agents, registry,
staging and lifecycle/receipt state **MUST** use the Issue route, not a PR.
Push checks compare changed canonical source digests with lifecycle and
receipt evidence. These are repository admission checks, not an alternate
authenticated estate registry. Evidence:
`rar-ref/.github/workflows/notary-policy.yml:12-47`,
`rar-ref/scripts/check_notarized_changes.py:41-101`,
`rar-ref/scripts/check_notarized_changes.py:213-248`.

Published agent paths and names **MUST NOT** be moved, renamed or deleted.
The append-only `state/published_paths.json` records path-to-
`{name, first_seen}`; update adds new paths without overwriting existing
records. Retirement replaces executable source with a same-path
`RAR_TOMBSTONE` notice and removes it from lookups. Source updates remain
in-place with version increases and admission evidence. The append-only
property is the path ledger and Git history, not immutable source bytes at
a moving branch URL. Evidence:
`rar-ref/CONSTITUTION.md:918-979`,
`rar-ref/scripts/check_url_stability.py:123-213`.

## 8. Rebuilding and publication

From an empty directory, the structure can be assembled without guessing
an agent package format: write the section 3 source under its namespaced
path; derive its registry record using section 4; write pack files and
their section 5 description if packs are wanted; render paired tickets;
then project the registry into the section 6 static files. An initially
unnotarized source is explicitly `legacy_active`, not an invented receipt.
The observed separation is source -> registry -> static projections.
Evidence: `rar-ref/build_registry.py:807-816`,
`rar-ref/build_registry.py:940-979`,
`rar-ref/build_registry.py:1103-1140`,
`rar-ref/scripts/build_static_api.py:517-562`,
`rar-ref/tools/build_agent_pages.py:220-231`.

For the observed implementation, the publication order is:

```bash
python3 security_scan.py
python3 tools/sync_layers.py --check
python3 build_registry.py
python3 scripts/check_url_stability.py --update
python3 scripts/build_pokedex_api.py
python3 scripts/build_skills_catalog.py
python3 scripts/build_static_api.py
```

CI checks receipts before rebuilding, checks generated layer facts before
registry construction, records newly published paths on main, and commits
the resulting registry, tickets and API projections. Full Git history is
used for publication provenance. The commands above describe an existing
checkout's procedure, not scripts supplied by this documentation-only
profile. Evidence:
`rar-ref/.github/workflows/build-registry.yml:68-159`,
`rar-ref/.github/workflows/build-registry.yml:166-188`.

The observed descriptor declares **`rapp-static-api/1.0`**, not 1.1.
The applicable pattern is ordinary static reads and regenerated discovery
JSON; `registry.json` is the primary catalog input to the static builders,
not the sole input to the entire publication. Repetition preserves
selection and identity for unchanged inputs, but **not byte-identical
output**: registry and API timestamps are regenerated, status hashes
include those timestamps, and previous registry/history can affect
projections. Agent ticket generation itself avoids unchanged writes.
Evidence: `rar-ref/scripts/build_static_api.py:700-714`,
`rar-ref/scripts/build_static_api.py:479-485`,
`rar-ref/build_registry.py:947-961`,
`rar-ref/build_registry.py:1437-1440`,
`rar-ref/tools/build_agent_pages.py:220-231`.

There is no tracked root `versions/` in the observed checkout, and neither
registry nor static writer creates one. Publication uses in-place generated
files, retained source URLs, Git commits, receipts, and optional
`state/releases.json`. This draft therefore makes **no claim of an
implemented append-only `versions/` contract**. The writer boundaries and
history inputs are evidenced by
`rar-ref/build_registry.py:1487-1541`,
`rar-ref/scripts/build_static_api.py:820-847`,
`rar-ref/scripts/check_url_stability.py:123-178`.

An egg's transport and a layer's host authorization stay with their linked
profiles. A pack listing, ticket, passing file hash, or notarization is not
proof that a layer passed a host gate or that user data belongs in its code.
RAR itself states that catalog admission is not runtime or protocol
certification, and distinguishes health from behavioral proof.
Evidence: `rar-ref/scripts/build_static_api.py:809-816`,
`rar-ref/LAYERS.md:38-51`,
`rar-ref/LAYERS.md:96-106`.

## 9. Conformance

This draft has no new schema, executable validator, or signed adoption.
The following are acceptance observations for the structure, not a claim
that passing parent-protocol vectors certifies a RAR.

1. A source scan and registry build **MUST** finish successfully; recorded
   manifest/runtime validation errors, same-version changed bytes, duplicate
   labels, mismatched lifecycle evidence, and integer seed collisions are
   refusal cases. Failure to extract a manifest from an ordinary source
   file can instead skip that file after a diagnostic; successful exit
   alone does not establish that every candidate was indexed.
   Evidence: `rar-ref/build_registry.py:1080-1101`,
   `rar-ref/build_registry.py:86-109`,
   `rar-ref/build_registry.py:1044-1060`,
   `rar-ref/build_registry.py:1327-1364`,
   `rar-ref/build_registry.py:1549-1567`.
2. A pack with a missing or changed listed file **MUST** appear unverified,
   not be silently corrected. Invalid retirement metadata or a starter
   reaching a retired pack **MUST** fail the build.
   Evidence: `rar-ref/build_registry.py:546-651`,
   `rar-ref/build_registry.py:1476-1483`.
3. Ticket pages **MUST** retain both the human and plain-text forms; a
   metadata-only stub **MUST NOT** be presented as executable source.
   Evidence: `rar-ref/tools/build_agent_pages.py:96-117`,
   `rar-ref/tools/build_agent_pages.py:217-231`.
4. Static builders **MUST** keep their owned files separate. A missing
   registry, empty agent list or invalid marketplace input **MUST** fail
   the headless build. A successful `--check` means computation succeeded,
   not that existing static files are current.
   Evidence: `rar-ref/scripts/build_static_api.py:488-546`,
   `rar-ref/scripts/build_static_api.py:820-847`.
5. Admission **MUST** bind the exact changed bytes, lifecycle state,
   identity and approval, and **MUST NOT** bypass the Issue-only protected
   state check. Published-path checks **MUST** reject vanished paths and
   changed recorded identities. Evidence:
   `rar-ref/scripts/check_notarized_changes.py:41-101`,
   `rar-ref/scripts/check_notarized_changes.py:213-248`,
   `rar-ref/scripts/check_url_stability.py:181-226`.

These observations do not certify process liveness, model behavior,
installation success, cryptographic publisher authentication, host gates,
offline possession of the complete RAR implementation, or an exact visual
clone. The distinction between discovery and measured runtime evidence is
explicit in the source.
Evidence: `rar-ref/scripts/build_static_api.py:263-279`,
`rar-ref/scripts/build_static_api.py:809-816`,
`rar-ref/LAYERS.md:38-51`.

## Open questions for Kody

- Should the static publication be upgraded to `rapp-static-api/1.1`, with
  an actual append-only `versions/` layout and a single-input,
  timestamp-stable build? The observed implementation does not supply
  those guarantees; this draft deliberately does not prescribe them.
- May this change add a RAR-specific JSON Schema and executable conformance
  runner, and update the profile-index validation/anchor inputs as needed?
  The existing `protocols/index.json` format requires both a schema path
  and hash and a conformance command for every entry. This documentation
  draft cannot truthfully supply them within a SPEC/README/index-only edit.
- Should the parent repository carry the exact RAR builder and its SDK,
  including presentation/ranking rules and the complete admission workflow?
  This draft defines the structure, integer seed and mnemonic words, not
  all implementation bytes; exact cold reconstruction of the current
  service and admission automation still needs those artifacts.
- Is `legacy_active` still allowed for new instances, or should every
  initial agent require Issue admission? The builder accepts missing
  lifecycle records today; the publication gate is stricter for changes.
- Should the lean API carry `_stub_sha256` and lifecycle/receipt evidence,
  instead of exposing an empty source digest for gated entries?
- Should pack validation reject malformed JSON, unknown includes, cycles,
  missing replacements, unsafe file paths, and seeded-pack collisions
  against converged agents as well as ordinary agents? The current
  projection does not consistently enforce those stronger conditions.
- Should an ordinary agent's syntax/compile error or unreadable literal
  manifest become a hard build failure instead of silently omitting that
  candidate after a diagnostic?
- Should failed registry construction avoid replacing `registry.json`,
  and should static `--check` compare committed output instead of only
  computing it? Those are proposed changes, not guarantees of this draft.
- What is the intended pack-to-egg mapping, if any? Neither file
  verification nor the layer runtime profile defines a pack installer or
  turns a discovery pack into execution authority.
