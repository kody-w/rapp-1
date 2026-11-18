# rapp-exhaust/1: the writer says how long its exhaust lives

Status: **staging** (proposed 2026-11-18; dogfooded on one estate machine). It moves past staging only by Kody's ruling.

## Why

A Brainstem, its climbs and its watchers make exhaust all day: transcripts, scores, screenshots, repo copies.
Nothing said how long any of it lives, so every loop kept everything. One estate Mac mini reached 100% full
(127 MB free of 228 GB) from a screenshot every minute and a 420 MB repo copy per climb run, and its phone
bridge stopped having room to work. Others paid for this lesson first: logrotate and journald (the writer
declares retention, one job enforces a count or age cap), Docker prune (rebuildable layers are cheap to drop),
git (never drop work that exists nowhere else).

## The rule

Any folder that collects exhaust carries one file, `.exhaust.json`, written by whatever writes the folder:

```json
{"schema": "rapp-exhaust/1", "kind": "picture", "keep": {"last": 20, "hours": 2}, "match": "*.png"}
```

| kind | what it is | what a keeper may do |
|---|---|---|
| `record` | transcripts, scores, decisions, frames: the useful exhaust | never remove it (shelve it, as lungs does, if room is short) |
| `rebuildable` | repo copies, packages, builds, per-request scratch already summarised in a record | remove past the limit; a folder holding git work only when clean and fully pushed |
| `picture` | screenshots, video, frames-as-images | remove past the limit |

- `keep.last N` keeps the N newest entries; `keep.hours H` keeps anything touched in the last H hours.
  Both given: an entry stays if either keeps it. Neither given: the last 7 days stay.
- Entries are the folder's direct children (a file or a whole sub-folder), aged by modification time.
- `match` (optional) narrows which children a rule covers. `rules` (optional) is a list of such rules when one
  folder holds several kinds.
- A folder with no `.exhaust.json` is never touched. Silence means keep.
- The rule owns its whole folder; sub-folders are not searched for further rules.

## Where it runs

Nothing here touches the grail or the `agent.py` + `/chat` contract. Enforcement is userland: the reference keeper
is lungs (`keep.py scan` shows what would go, `keep.py run` does it), run hourly. Writers only add one small file.
