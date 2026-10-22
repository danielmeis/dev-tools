# audit-packages

Recursively finds every npm/composer package under a directory path and runs a
vulnerability audit on each one, with a short pass/fail summary.

## Requirements

- `bash`, `node` 18+ on `PATH`
- `npm` and/or `composer` on `PATH`, depending on which `--audit` types you use
- Network access (audits query the npm/Packagist advisory databases; the EPSS
  section also queries OSV.dev and FIRST.org unless `--no-epss` is given)

Each npm package needs `package.json` and `package-lock.json`; each Composer
package needs `composer.json` and `composer.lock`. Packages missing a lockfile
are skipped and reported separately. Audits use the lockfile, so installed
dependencies (`node_modules` or `vendor`) are not required.

## Usage
_defaults to `npm` audit type and `low` severity and above (i.e. any real vulnerability, excluding `info`)_

```sh
./audit-packages.sh <path> [--level=<info|low|moderate|high|critical>] [--audit=TYPE[,TYPE...]] [--epss[=THRESHOLD]] [--epss-all] [--no-epss] [--no-git-check] [--check-remote] [--require-default-branch] [--yes] [--timeout=SECONDS]
```

### Examples

```sh
./audit-packages.sh ../../my-project
./audit-packages.sh ../../my-project/wp-content/plugins/my-plugin
./audit-packages.sh ../../my-project --level=high
./audit-packages.sh ../../my-project --audit=composer
./audit-packages.sh ../../my-project --audit=npm,composer
./audit-packages.sh ../../my-project --epss=0.05
./audit-packages.sh ../../my-project --epss-all
./audit-packages.sh ../../my-project --no-epss
./audit-packages.sh ../../my-project --check-remote
```

### Options

- `--level=LEVEL` — only flag vulnerabilities at or above this severity
  (default: `low`, i.e. any vulnerability)
- `--audit=TYPE` — which audit(s) to run: `npm`, `composer` (default: `npm`)
- `--epss[=N]` — EPSS section (on by default); lists high/critical advisories
  with an exploit probability at or above `N` (0-1, default `0.01`)
- `--epss-all` — list every matching EPSS advisory and all its paths instead of
  the top 10 (5 paths each)
- `--no-epss` — skip the EPSS lookup (no network calls beyond the audits)
- `--no-git-check` — skip the read-only repo state check (see below)
- `--check-remote` — in the repo check, ask each remote for its current
  default-branch commit (`git ls-remote`, read-only, needs network) instead of
  trusting local remote refs
- `--require-default-branch` — exit `3` if any repo needs attention (only when
  no vulnerabilities were flagged)
- `-y`, `--yes` — don't ask to continue when repos need attention
- `--timeout=SECS` — give up on a single `npm audit`/`composer audit` after `SECS`
  seconds and list it under errors (default `90`, `0` = no limit)

In a terminal, a `[####------] 5/14` counter tracks the repo check and the
audits. If one command runs longer than 3s, the line shows how long it has
been waiting and when it will give up, so a stall is visible. Non-terminal runs
get plain `Auditing (...)` log lines instead.
- `--no-color` — disable colors (also respects `NO_COLOR`); emoji are still printed
- `-h`, `--help` — show help

## Repo state check

Before auditing, each git repo containing a scanned manifest is checked
**read-only** (no checkout, fetch, or index refresh) and reported if it is:

- on a branch other than the default (from `origin/HEAD`, falling back to
  `origin/main`/`origin/master`) or on a detached HEAD
- behind or ahead of the default branch
- carrying uncommitted changes to tracked files (manifests/lockfiles are called out)

By default, behind/ahead uses local remote refs, which are only as fresh as the
last fetch; repos not fetched in over a day are counted so a stale result isn't
mistaken for "in sync". `--check-remote` asks the remote directly via
`git ls-remote` for an up-to-date answer, still without touching the repo.

If any repo needs attention and stdin is a terminal, you are asked
`Continue with the audit anyway? [y/N]`; declining exits `3` before any audit
runs. Piped/CI runs are never prompted, and `--yes` skips the prompt.

## Summary sections

After the per-package report, the script prints:

- **High/Critical totals** — vulnerability counts per severity across flagged
  packages. These count vulnerable *packages* as reported by `npm audit` /
  `composer audit`.
- **EPSS** — unique high/critical *advisories* whose
  [EPSS](https://www.first.org/epss/) probability meets the threshold, highest
  first, with the repo paths where each was found. Advisories are labelled
  `🚩 PROD` (sorted first) or `dev-only`. The label comes from the lockfile
  (`dev: true` in `package-lock.json`, `packages-dev` in `composer.lock`); a
  dev-only package can still ship if CI/deploy installs dev packages or bundles
  them into client code. Advisories without a CVE or EPSS score are counted as
  unscored, not dropped.

Run `./audit-packages.sh --help` for the full help text, including which
directories are skipped (`node_modules`, `vendor`, `build`, etc.) and exit
codes.

This is a manual, report-only tool — it never installs or modifies anything.

## Exit codes

- `0` — no packages flagged at the given `--level`
- `1` — at least one package was flagged
- `2` — usage error
- `3` — declined the repo-state prompt, or `--require-default-branch` is set,
  a repo needs attention, and no vulnerabilities were flagged
