# audit-packages

Recursively finds every npm/composer package under a directory path and runs a
vulnerability audit on each one, with a short pass/fail summary.

## Requirements

- `bash`, `node` on `PATH`
- `npm` and/or `composer` on `PATH`, depending on which `--audit` types you use
- Network access (audits query the npm/Packagist advisory databases)

Each npm package needs `package.json` and `package-lock.json`; each Composer
package needs `composer.json` and `composer.lock`. Packages missing a lockfile
are skipped and reported separately. Audits use the lockfile, so installed
dependencies (`node_modules` or `vendor`) are not required.

## Usage
_defaults to `npm` audit type and `low` severity and above (i.e. any real vulnerability, excluding `info`)_

```sh
./audit-packages.sh <path> [--level=<info|low|moderate|high|critical>] [--audit=TYPE[,TYPE...]]
```

### Examples

```sh
./audit-packages.sh ../../my-project
./audit-packages.sh ../../my-project/wp-content/plugins/my-plugin
./audit-packages.sh ../../my-project --level=high
./audit-packages.sh ../../my-project --audit=composer
./audit-packages.sh ../../my-project --audit=npm,composer
```

### Options

- `--level=LEVEL` — only flag vulnerabilities at or above this severity
  (default: `low`, i.e. any vulnerability)
- `--audit=TYPE` — which audit(s) to run: `npm`, `composer` (default: `npm`)
- `--no-color` — disable colored/emoji output (also respects `NO_COLOR`)
- `-h`, `--help` — show help

Run `./audit-packages.sh --help` for the full help text, including which
directories are skipped (`node_modules`, `vendor`, `build`, etc.) and exit
codes.

This is a manual, report-only tool — it never installs or modifies anything.

## Exit codes

- `0` — no packages flagged at the given `--level`
- `1` — at least one package was flagged
- `2` — usage error
