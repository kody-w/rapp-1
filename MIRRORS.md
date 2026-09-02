# Mirrors — more than one home

The chain of record is content-addressed, so any complete clone is as good as the
origin. What a clone cannot survive is losing the *place people look*. These are the
places, in the order a stranger should try them.

| where | what | status |
|---|---|---|
| https://github.com/kody-w/rapp-1 | canonical, protected main, CI oracles | live |
| https://kody-w.github.io/rapp-1/ | rendered site, beacon, chain, book | live |
| https://archive.softwareheritage.org/browse/origin/?origin_url=https://github.com/kody-w/rapp-1 | permanent archive of every commit (Software Heritage) | requested 2026-09-01 |
| https://web.archive.org/web/*/kody-w.github.io/rapp-1/* | Wayback captures of the site, beacon, and chain | captured 2026-09-01 |
| Codeberg / GitLab | git mirrors pushed on every commit to main | **not yet configured** |
| the printed book (`book/`) | paper; survives every platform | in print |

## Configure the git mirrors (owner, once)

1. Create an empty repository on the mirror host (Codeberg and GitLab both work; any git
   host with HTTPS push does).
2. Create a push token there scoped to that one repository.
3. In this repository's settings add a secret named `MIRROR_PUSH_URLS` whose value is
   one or more space-separated push URLs of the form
   `https://<user>:<token>@codeberg.org/<user>/rapp-1.git`.
4. Run the **Mirror** workflow once by hand; from then on every push to main mirrors.

The workflow pushes with `--force-with-lease`, so a mirror that diverged (someone pushed
to it directly) refuses rather than being silently overwritten. Mirrors are discovery,
never authority: the anchor's beacon and the estate's signed registry decide what is canon.

## Re-request archival after a big change

```bash
curl -X POST https://archive.softwareheritage.org/api/1/origin/save/git/url/https://github.com/kody-w/rapp-1/
curl -s https://web.archive.org/save/https://kody-w.github.io/rapp-1/anchor/chain.jsonl -o /dev/null
```
