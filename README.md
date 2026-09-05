# dev-tools

A collection of small, generic, standalone dev tools. Each tool lives in its own
folder with no dependencies on the others.

## Tools

- [audit-packages](audit-packages/README.md) — recursively scans a directory
  for npm/composer packages and reports known vulnerabilities per package.

## Usage

Clone the repo and run a tool's script directly, e.g.:

```sh
./audit-packages/audit-packages.sh /path/to/project
```

See each tool's own README for details and options.

## License

MIT — see [LICENSE](LICENSE).
