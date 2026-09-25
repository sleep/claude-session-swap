# ccswitch

Manage multiple Claude Code and Kimi Code subscription accounts on macOS and Linux.

Claude Code stores its login credentials in `~/.claude/.credentials.json` plus an `oauthAccount` entry in `~/.claude.json` — one account at a time. `ccswitch` saves each login as a named profile and swaps them in and out, so you can move between (say) a personal and a work subscription without re-authenticating every time. Profiles are plain JSON, so exported profiles move cleanly between machines and platforms.

Kimi Code gets the same treatment: prefix any command with `kimi` (or use the `kcswitch` bin alias) and every command below works against Kimi Code logins — see [Kimi Code accounts](#kimi-code-accounts).

On macOS, Claude Code itself prefers the Keychain. `ccswitch` never writes to it: a lingering Keychain entry is read once as the freshest copy of your tokens, then evicted on the next switch so Claude Code falls back to the credentials file and the file stays the single source of truth. Kimi Code is file-only on every platform, so none of that applies to `kimi` commands.

## Install

Requires Node.js ≥ 20. Credentials are managed through the `~/.claude/.credentials.json` and `~/.kimi-code/credentials/kimi-code.json` files on every platform.

```sh
git clone <this repo>
cd claude-session-swap
npm link        # puts `ccswitch`, `kcswitch` and `ccswitch-server` on your PATH
```

No dependencies to install: the tool is zero-dependency by design (`ccswitch.mjs` plus two small modules under `lib/`), since it handles OAuth refresh tokens and every third-party package would be supply-chain attack surface.

## Usage

```
ccswitch                      pick a profile interactively and switch to it
ccswitch <name>               switch to profile <name>
ccswitch switch <name>        same as above
ccswitch login <name>         log a new account in and save it as <name> (--force re-logs into an existing profile)
ccswitch save <name>          save the current login as <name> (--force overwrites)
ccswitch run <name> -- [...]  one-off claude session as <name> (no global switch)
ccswitch list                 show saved profiles
ccswitch usage                show 5h/7d/fable quota for every profile (refreshes expired tokens)
ccswitch delete <name>        delete a profile (--force skips confirmation)
ccswitch export <name> [file] write a profile to a plaintext file (--move retires it here)
ccswitch import <name> [file] load a profile from such a file (--force overwrites)
ccswitch export-all [file]    write ALL profiles + active pointer to one file (--move retires them here)
ccswitch import-all [file]    merge such a file into this machine (--force overwrites existing profiles)
ccswitch encrypt              encrypt profiles, backups and future exports with a passphrase
ccswitch decrypt              turn passphrase encryption back off (rewrites the store as plaintext)
ccswitch sync                 pull the newest token chains from your sync server and push local changes
ccswitch sync setup           connect this machine to a ccswitch-server using your gpg key
ccswitch sync status          show the sync server, key, vault version and unresolved chains
ccswitch sync off             stop syncing on this machine (keeps local profiles and the vault)
```

Every command accepts `--dry-run` to print what it would do without touching anything. Every command also works for Kimi Code by prefixing with `kimi` — `ccswitch kimi save work`, `ccswitch kimi usage`, etc.

### Getting started

Save your current login, then add a second account:

```sh
ccswitch save personal # snapshot the login you're already using

ccswitch login work    # launches `claude /login` — complete it and exit (/exit)

ccswitch list
ccswitch personal      # switch back
```

### One-off sessions without switching

`ccswitch run` launches Claude Code with `CLAUDE_CONFIG_DIR` pointed at an isolated per-profile directory, so your global login is untouched:

```sh
ccswitch run work -- -p "summarize this repo"
```

### Quota across accounts

`ccswitch usage` shows every profile's rate-limit windows without switching, so you can see which account has headroom before starting a session:

```
   name      email          5h          resets    7d          resets    fable       resets    status
*  personal  me@gmail.com   ███▏   63%  in 2h04m  █      19%  in 5d21h  ██▌    49%  in 4d02h  ok
   work      me@corp.com    ██▉    58%  in 3h27m  ████▎  84%  in 5d23h  -           -         ok (refreshed)
   old       old@gmail.com  -           -         -           -         -           -         logged out
```

`fable` is Fable's own weekly cap, reported separately from the general 7d window; it shows `-` on accounts that have no such cap. It queries Anthropic's OAuth usage endpoint with each profile's stored token. Expired access tokens are refreshed first, and the rotated token pair is written back to the profile *before* it's used — so a crash can never lose a login. Valid tokens are never refreshed (no pointless rotation), and a profile whose chain is dead just shows `logged out` without breaking the others.

Each successful lookup is cached per profile in `~/.cache/ccswitch/usage/` (or `$XDG_CACHE_HOME/ccswitch/usage/`). If the usage endpoint answers `429`, that profile shows its last known numbers with a status like `rate limited, cached 12m ago` instead of an error. Reset countdowns stay accurate because they are stored as absolute times. Other failures never fall back to the cache, so stale numbers can't hide a real problem.

### Kimi Code accounts

Prefix any command with `kimi` and it operates on Kimi Code logins instead, with the full feature set — switch, save, login, run, list, usage, delete, export/import, export-all/import-all, encrypt/decrypt:

```sh
ccswitch kimi save main      # snapshot your current Kimi Code login
ccswitch kimi login alt      # runs `kimi login` (device-code flow) and saves the new account
ccswitch kimi usage          # quota across all kimi profiles
ccswitch kimi alt            # switch
```

Installed via `npm link`, the `kcswitch` bin alias makes kimi the default target, so `kcswitch list` equals `ccswitch kimi list`. (The prefix means a claude profile literally named `kimi` must be switched via `ccswitch switch kimi`.)

Differences from the claude side, all consequences of how kimi stores its login:

- **File-only store.** The live login is `~/.kimi-code/credentials/kimi-code.json`; there is no Keychain path and no identity file. The account identity is the `sub` claim of the access-token JWT.
- **Display names come from the network.** Tokens carry no email, so `list`/`usage` show the account's nickname, level and email from a best-effort `GET /coding/v1/me` (cached in the profile after `login` and each successful `usage`). Until then the bare user id is shown.
- **Region is recorded per profile.** kimi's deployment is either mainland-cn (`kimi.com`, the default) or global (`kimi.ai`); the endpoints are read from `~/.kimi-code/config.toml` (or `KIMI_CODE_BASE_URL`/`KIMI_CODE_OAUTH_HOST`) at save/login time so token refreshes and usage lookups hit the right one. Pass `--region global` to `ccswitch kimi login` for a first-time kimi.ai login: `ccswitch kimi login work --region global`.
- **`run` isolates a whole `KIMI_CODE_HOME`.** `ccswitch kimi run work -- -p "..."` launches kimi with `KIMI_CODE_HOME` pointed at a per-profile directory containing the credentials file plus a minimal seeded `config.toml` pinning the region endpoints (your own `config.toml` is never copied — it can hold API keys). Rotated tokens are saved back into the profile on exit, same as claude.
- **`usage` shows kimi's quota shape**: the weekly quota window, any extra scoped limit windows, and the booster (pay-as-you-go) balance:

```
   name  account  week        resets    limits                  booster  status
*  main  Shy      ██▉    58%  in 3d04h  5h ▏       4% in 1h12m  $9.50    ok
   alt   u2abc…   -           -         -                     -        logged out
```

Kimi refresh tokens rotate on refresh exactly like claude's, so all the multi-machine rules below apply unchanged: one chain, one machine; `export --move` / `export-all --move` to migrate.

### Using accounts on more than one machine

The underlying rule: **a token chain copied by hand works from exactly one machine.** OAuth refresh tokens rotate on every refresh, so the moment two machines hold the same chain, the first refresh strands the other machine's copy, and replaying a stranded chain makes Anthropic revoke the account's grant everywhere (that shows up as machines suddenly deauthorized). There are three ways to live with that:

**Sync (recommended for machines you use interchangeably).** Run your own `ccswitch-server` and connect each machine with `ccswitch sync setup`; every command then pulls the newest chains first and pushes what it changed. See [Syncing between machines](#syncing-between-machines).

**Both machines in active use, no server: log in separately on each.** Run `ccswitch login <name>` per account on the second machine. Each login creates an independent chain, and Anthropic keeps many chains alive per account, so machines logged in this way never log each other out. Never export a profile to a machine that is already using that account.

**Migrating to a new machine: move, don't copy.**

```sh
ccswitch export-all --move      # writes ccswitch-all.ccswitch.json, retires local copies
# copy it over a trusted channel, then on the other machine:
ccswitch import-all ccswitch-all.ccswitch.json
```

`--move` marks the exported profiles as moved on the source machine (and logs it out of the active one), so it can never refresh, and thereby revoke, a chain that now lives elsewhere. A moved profile refuses `switch`/`run`, shows as `moved` in `list` and `usage`, and can be revived by importing it back or with a fresh `ccswitch login`. Single profiles move the same way with `ccswitch export <name> --move` + `ccswitch import <name> <file>`.

`import-all` merges: profiles that already exist on the target machine are skipped (pass `--force` to overwrite them; moved tombstones are overwritten without it), and the exported active pointer is only adopted if the target has no active profile. If an imported profile matches the login already live on the target machine, the machine's own chain is kept, since the imported copy would die on the source machine's next refresh anyway. Backups and per-profile run dirs are machine-local and not included.

Exported files hold live tokens in plaintext — treat them like passwords (or encrypt the store first, below).

### Syncing between machines

Sync mirrors your profiles through a small server you host, so the chain one machine just rotated is what the next machine picks up. Your OpenPGP key is the only credential: requests are signed with it, the vault is encrypted (and signed) to it, and the private key never leaves your machines. The server stores ciphertext it cannot read, keyed by your key's fingerprint, and it never sees profile names, emails or tokens. A full compromise of the server yields public keys and encrypted blobs.

Both ends shell out to `gpg` (GnuPG 2.2 or newer), which keeps ccswitch dependency-free and lets you use a key that already lives in your keyring, hardware token included. Ed25519 keys are recommended; `sync setup` can generate one. The same secret key has to be present on every machine you sync (export it with `gpg --export-secret-keys --armor <fingerprint>` and import it on the other side over a channel you trust).

**Server, once, on a box the clients can reach:**

```sh
ccswitch-server setup    # checks for gpg, asks host/port, mints the secret URL
ccswitch-server start    # or: ccswitch-server --data-dir /srv/ccswitch start
ccswitch-server url      # prints the client URL again
```

The server listens on plain HTTP (default `127.0.0.1:8787`); put a TLS reverse proxy in front for anything beyond localhost, or bind to `0.0.0.0` if you accept that. Every route sits under a random 64-character path, so the URL is the only thing standing between strangers and the vault store. Treat it as a secret: `sync setup` prompts for it (so it stays out of shell history), but a reverse proxy's access log will contain it. Registration is open; the server caps itself at 1024 vaults of 1 MiB each, and `ccswitch-server rotate-url` mints a fresh path if someone ever finds the old one (every client then needs `sync setup` again). Vaults live in `~/.ccswitch-server/vaults/<fingerprint>/` (`CCSWITCH_SERVER_DIR` or `--data-dir` to move them); the server is a single process by design.

**Each machine:**

```sh
ccswitch sync setup      # picks your gpg key (or generates one), asks for the server URL, syncs
ccswitch sync status
ccswitch kimi sync setup # the kimi store has its own vault under the same key
```

From then on every command except the read-only and local-file ones (`list`, `export*`, `import*`, `encrypt`, `decrypt`) pulls before it runs and pushes afterwards if it changed any tokens. A pull is skipped when the last sync was under a minute ago, so statusline scripts calling `ccswitch usage` do not hammer the server. Sync trouble (server down, gpg unavailable, wrong URL) is printed as a warning and the command carries on with the local profiles; `--dry-run` never touches the network. `ccswitch sync` runs a sync on demand, and `ccswitch sync off` disconnects this machine without touching its profiles or the vault.

**How conflicts are handled.** Merging is three-way against what each machine last synced: a profile changed on only one side simply wins, whatever the clocks say, and a delete travels as a tombstone so the profile does not come back from another machine. If two machines both refreshed the same chain between syncs, neither copy is thrown away: the newer one becomes the profile's chain and the older is kept as a candidate. The next time that profile is used (or on `ccswitch sync`), ccswitch tests the candidates newest-first with a harmless quota request, refreshing only when a token has expired, and stops at the first one the provider still accepts. A superseded chain is never refreshed once a newer one has worked, because that is what trips the provider's reuse detection. `sync status` lists profiles with candidates still to be tested.

```
$ ccswitch work
"work": refreshed on both studio-3f9a and laptop-71c0; chain from laptop-71c0 is live
switched to "work" (w@example.com)
```

**What the server can and cannot do.** It can refuse to store anything, drop the vault, or serve an old copy; it cannot read or forge one. The plaintext inside the ciphertext names its vault and version, so a swapped or rolled-back blob is refused rather than merged, and a vault that is not signed by your own key is refused even though it decrypts. Requests carry a signed timestamp, so a captured request is useless after five minutes and a replayed push hits the version check.

### Encryption at rest (opt-in)

```sh
ccswitch encrypt   # prompts for a passphrase (twice) and seals the store
ccswitch decrypt   # rewrites everything back to plaintext
```

Once encrypted, profiles, backups and any new exports are sealed with scrypt-derived AES-256-GCM (`node:crypto`, still zero dependencies). Commands that need to read the store prompt for the passphrase; set `CCSWITCH_PASSPHRASE` (or `KCSWITCH_PASSPHRASE`) to skip the prompt in scripts. The live `~/.claude/.credentials.json` (and likewise `~/.kimi-code/credentials/kimi-code.json`) is **never** encrypted — the tool must read it as plaintext, so the active account's tokens are always exposed to your user account regardless. Encrypted exports can be imported on another machine with the same passphrase, even into an unencrypted store. The claude and kimi stores are encrypted independently (`ccswitch encrypt` vs `ccswitch kimi encrypt`) and may use different passphrases.

## How it works

- **Profiles** live as JSON files in `~/.claude-profiles/profiles/` (`~/.kimi-profiles/profiles/` for kimi), holding the credential payload and the `oauthAccount` identity, with `0600` permissions.
- **Switching** captures the live credentials, saves them back to the outgoing profile (only if the live identity still matches it), then writes the new profile's credentials to `~/.claude/.credentials.json` and surgically updates the single `oauthAccount` key in `~/.claude.json` via an atomic rename — the other ~95 keys (projects, history, settings) are never touched. On macOS any Keychain entry is evicted at the same time, so Claude Code reads the file. For kimi, switching only swaps `~/.kimi-code/credentials/kimi-code.json` — the token itself carries the account.
- **Run sessions** (`ccswitch run`) save refreshed tokens back into the profile when the session exits — OAuth refresh tokens are single-use, so without this the profile snapshot would go stale after the first in-session token refresh.
- **Backups**: every mutation (switch, login, delete) first writes a timestamped snapshot to the store's `backups/` directory, so any state is recoverable.
- **Safety checks**: a failed or abandoned `login` restores the previous credentials; switching warns if `claude`/`kimi` is currently running (open sessions keep the old account and may rewrite the stored credentials on token refresh); the active profile can't be deleted.
- **Sync** (opt-in) keeps `sync.json` next to `state.json`: server URL, key fingerprint, a label for this machine, the vault version last seen, per-profile digests from the last sync (the merge base) and delete tombstones. A `sync.lock` file keeps two ccswitch processes from syncing the same store at once.

### Configuration

Environment variables override the defaults (mainly useful for testing). The kimi side mirrors the claude side with a `KCSWITCH_` prefix:

| Variable | Default |
|---|---|
| `CCSWITCH_HOME` | `~/.claude-profiles` |
| `CCSWITCH_CREDENTIALS_FILE` | `~/.claude/.credentials.json` |
| `CCSWITCH_KEYCHAIN_SERVICE` | `Claude Code-credentials` (macOS migration/eviction only) |
| `CCSWITCH_CLAUDE_JSON` | `~/.claude.json` |
| `CCSWITCH_CLAUDE_BIN` | `claude` |
| `KCSWITCH_HOME` | `~/.kimi-profiles` |
| `KCSWITCH_CREDENTIALS_FILE` | `$KCSWITCH_KIMI_HOME/credentials/kimi-code.json` |
| `KCSWITCH_KIMI_HOME` | `$KIMI_CODE_HOME`, else `~/.kimi-code` |
| `KCSWITCH_KIMI_BIN` | `kimi` |
| `CCSWITCH_CACHE_DIR` | `$XDG_CACHE_HOME/ccswitch`, else `~/.cache/ccswitch` (usage cache, shared by both stores) |
| `CCSWITCH_PASSPHRASE` / `KCSWITCH_PASSPHRASE` | (unset — either works for either store) |
| `CCSWITCH_GPG_BIN` | `gpg`, else `gpg2` (sync client and server) |
| `CCSWITCH_SERVER_DIR` | `~/.ccswitch-server` (ccswitch-server data: config, vaults) |

Region endpoints for kimi follow kimi's own resolution: `KIMI_CODE_BASE_URL` / `KIMI_CODE_OAUTH_HOST` (or `KIMI_OAUTH_HOST`), then the persisted login in `~/.kimi-code/config.toml`, then the mainland-cn defaults.

## Development

```sh
npm test    # node --test
```

The gpg suite runs against the real `gpg` binary in throwaway keyrings and is skipped when gpg is not installed. `lib/sync-protocol.mjs` holds the pure envelope and merge logic, `lib/gpg.mjs` the gpg wrapper, and `sync-server.mjs` the server.

## License

MIT
