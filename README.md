# Custom importer  

This tool reads Apache access logs of Matomo tracking requests and replays them into Matomo's Tracking API, preserving original timestamps and IP (when allowed).

# Install
Rename the plugin folder to just CustomImporter


## Requirements
- Run inside the Matomo container.
- A valid `token_auth` is required for non-dry runs.


## Usage

Basic:
```bash
./console customimporter:import \
  --limit=100 \
  --matomo-url=https://matomo.loc \
  --token-auth=YOUR_TOKEN \
  plugins/CustomImporter/example-data/access.log.1
```

Options:
- `--dry-run`: print replay URLs without sending
- `--limit`: process only N lines
- `--matomo-url`: base URL to your Matomo (required unless `--dry-run`)
- `--token-auth` / `--token-auth-env`: REQUIRED for actual import; needed for `cdt`/`cip`
- `--idsite`: fallback site id when not present in the log
- `--override-idsite`: force a specific site id (overrides original)
- `--only-idsite`: process only log lines whose original query has this `idsite`
- `--strip-auth-fields`: remove `cip`/`cdt` if no token is provided (avoids tracker errors, but loses original IP/time)
- `--prefer-post`: send tracking via POST (safer for long URLs)
- `--no-xff`: do not send `X-Forwarded-For` header (even with token)
- `--sleep-us`: microseconds to sleep between requests
- `--no-fallback`: disable fallback retry (keeps exact original params; may fail more)

## Timestamp handling (cdt)
- `cdt` is always set from the original access log datetime in UTC, formatted as `YYYY-mm-dd HH:MM:SS`.
- When `cdt` is set we remove `h/m/s` query params to avoid conflicts.
- If `cdt` is older than 24h, a valid `token_auth` is required by Matomo.

## Progress reporting
- Prints `Total lines to process: N` at start.
- Prints progress at every 1%: `Progress: X% (processed/total) - elapsed: Ys`.

## Examples

Using an env var for token:
```bash
export MATOMO_TOKEN=YOUR_TOKEN
./console customimporter:import \
  --limit=1000 \
  --matomo-url=https://matomo.loc \
  --token-auth-env=MATOMO_TOKEN \
  --prefer-post \
  plugins/CustomImporter/example-data/access.log.1
```

Filter by original `idsite`:
```bash
./console customimporter:import \
  --only-idsite=2 \
  --matomo-url=https://matomo.loc \
  --token-auth=YOUR_TOKEN \
  plugins/CustomImporter/example-data/access.log.1
```

If you cannot provide a token (not recommended), strip auth fields:
```bash
./console customimporter:import \
  --limit=100 \
  --matomo-url=https://matomo.loc \
  --strip-auth-fields \
  plugins/CustomImporter/example-data/access.log.1
```

## After import
For historical backfills, run archiving so reports include newly imported dates:
```bash
./console core:archive
```