# ccswitch

Manage multiple Claude Code subscription accounts on macOS and Linux.

Claude Code stores its login credentials in `~/.claude/.credentials.json` plus an `oauthAccount` entry in `~/.claude.json` — one account at a time. `ccswitch` saves each login as a named profile and swaps them in and out, so you can move between (say) a personal and a work subscription without re-authenticating every time. Profiles are plain JSON, so exported profiles move cleanly between machines and platforms.

On macOS, Claude Code itself prefers the Keychain. `ccswitch` never writes to it: a lingering Keychain entry is read once as the freshest copy of your tokens, then evicted on the next switch so Claude Code falls back to the credentials file and the file stays the single source of truth.

## Install

Requires Node.js ≥ 20. Credentials are managed through the `~/.claude/.credentials.json` file on every platform.

```sh
git clone <this repo>
cd claude-session-swap
npm link        # puts `ccswitch` on your PATH
```

No dependencies to install — the tool is a single zero-dependency script by design, since it handles OAuth refresh tokens and every third-party package would be supply-chain attack surface.

## Usage

```
ccswitch                      pick a profile interactively and switch to it
ccswitch <name>               switch to profile <name>
ccswitch switch <name>        same as above
ccswitch login <name>         log a new account in and save it as <name>
ccswitch save <name>          save the current login as <name> (--force overwrites)
ccswitch run <name> -- [...]  one-off claude session as <name> (no global switch)
ccswitch list                 show saved profiles
ccswitch delete <name>        delete a profile (--force skips confirmation)
ccswitch export <name> [file] write a profile to a plaintext file (default <name>.ccswitch.json)
ccswitch import <name> [file] load a profile from such a file (--force overwrites)
```

Every command accepts `--dry-run` to print what it would do without touching anything.

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

### Moving a profile to another machine

```sh
ccswitch export work            # writes work.ccswitch.json
# copy it over a trusted channel, then on the other machine:
ccswitch import work work.ccswitch.json
```

Exported files hold live tokens in plaintext — treat them like passwords.

## How it works

- **Profiles** live as JSON files in `~/.claude-profiles/profiles/`, holding the credential payload and the `oauthAccount` identity, with `0600` permissions.
- **Switching** captures the live credentials, saves them back to the outgoing profile (only if the live identity still matches it), then writes the new profile's credentials to `~/.claude/.credentials.json` and surgically updates the single `oauthAccount` key in `~/.claude.json` via an atomic rename — the other ~95 keys (projects, history, settings) are never touched. On macOS any Keychain entry is evicted at the same time, so Claude Code reads the file.
- **Run sessions** (`ccswitch run`) save refreshed tokens back into the profile when the session exits — OAuth refresh tokens are single-use, so without this the profile snapshot would go stale after the first in-session token refresh.
- **Backups**: every mutation (switch, login, delete) first writes a timestamped snapshot to `~/.claude-profiles/backups/`, so any state is recoverable.
- **Safety checks**: a failed or abandoned `login` restores the previous credentials; switching warns if `claude` is currently running (open sessions keep the old account and may rewrite the stored credentials on token refresh); the active profile can't be deleted.

### Configuration

Environment variables override the defaults (mainly useful for testing):

| Variable | Default |
|---|---|
| `CCSWITCH_HOME` | `~/.claude-profiles` |
| `CCSWITCH_CREDENTIALS_FILE` | `~/.claude/.credentials.json` |
| `CCSWITCH_KEYCHAIN_SERVICE` | `Claude Code-credentials` (macOS migration/eviction only) |
| `CCSWITCH_CLAUDE_JSON` | `~/.claude.json` |
| `CCSWITCH_CLAUDE_BIN` | `claude` |

## Development

```sh
npm test    # node --test
```

## License

MIT
