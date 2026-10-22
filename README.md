# dev-tools

A collection of small, generic dev tools. Each tool lives in its own
self-contained folder (copy the whole folder) with no dependencies on the others.

## Tools

- [audit-packages](audit-packages/README.md) — recursively scans a directory
  for npm/composer packages and reports known vulnerabilities per package,
  ranked by exploit likelihood (EPSS), plus a read-only check of each repo's
  branch state.

## Requirements

Tool-specific requirements are in each tool's README. For `audit-packages`:
`bash` and `node` 18+, plus `npm` and/or `composer` (and optionally `git`).
It needs network access, including requests to OSV.dev and FIRST.org for EPSS
scores unless run with `--no-epss`; only public advisory IDs are sent.

## Usage

Clone the repo and run a tool's script directly, e.g.:

```sh
./audit-packages/audit-packages.sh /path/to/project
```

See each tool's own README for details and options.

## License

MIT — see [LICENSE](LICENSE).
