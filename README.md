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
npm link        # puts `ccswitch` and `kcswitch` on your PATH
```

No dependencies to install — the tool is a single zero-dependency script by design, since it handles OAuth refresh tokens and every third-party package would be supply-chain attack surface.

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

The one rule: **a token chain works from exactly one machine.** OAuth refresh tokens rotate on every refresh, so the moment two machines hold the same chain, the first refresh strands the other machine's copy, and replaying a stranded chain makes Anthropic revoke the account's grant everywhere (that shows up as machines suddenly deauthorized). There are two safe setups:

**Both machines in active use: log in separately on each.** Run `ccswitch login <name>` per account on the second machine. Each login creates an independent chain, and Anthropic keeps many chains alive per account, so machines logged in this way never log each other out. Never export a profile to a machine that is already using that account.

**Migrating to a new machine: move, don't copy.**

```sh
ccswitch export-all --move      # writes ccswitch-all.ccswitch.json, retires local copies
# copy it over a trusted channel, then on the other machine:
ccswitch import-all ccswitch-all.ccswitch.json
```

`--move` marks the exported profiles as moved on the source machine (and logs it out of the active one), so it can never refresh, and thereby revoke, a chain that now lives elsewhere. A moved profile refuses `switch`/`run`, shows as `moved` in `list` and `usage`, and can be revived by importing it back or with a fresh `ccswitch login`. Single profiles move the same way with `ccswitch export <name> --move` + `ccswitch import <name> <file>`.

`import-all` merges: profiles that already exist on the target machine are skipped (pass `--force` to overwrite them; moved tombstones are overwritten without it), and the exported active pointer is only adopted if the target has no active profile. If an imported profile matches the login already live on the target machine, the machine's own chain is kept, since the imported copy would die on the source machine's next refresh anyway. Backups and per-profile run dirs are machine-local and not included.

Exported files hold live tokens in plaintext — treat them like passwords (or encrypt the store first, below).

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

Region endpoints for kimi follow kimi's own resolution: `KIMI_CODE_BASE_URL` / `KIMI_CODE_OAUTH_HOST` (or `KIMI_OAUTH_HOST`), then the persisted login in `~/.kimi-code/config.toml`, then the mainland-cn defaults.

## Development

```sh
npm test    # node --test
```

## License

MIT
