#!/bin/bash
# Recursively finds every package manifest under a given path (skipping
# node_modules, vendor, build output, and native build/dependency dirs) and
# reports vulnerability audit results per package.
#
# Usage:
#   ./audit-packages.sh <path> [--level=<info|low|moderate|high|critical>] [--audit=TYPE[,TYPE...]]
#
# Examples:
#   ./audit-packages.sh ../../my-project
#   ./audit-packages.sh ../../my-project/wp-content/plugins/my-plugin
#   ./audit-packages.sh ../../my-project --level=high
#   ./audit-packages.sh ../../my-project --audit=composer
#   ./audit-packages.sh ../../my-project --audit=npm,composer
#
# Requirements: bash, node on PATH always; npm and/or composer on PATH depending
# on which --audit types are selected. Network access is required since both
# `npm audit` and `composer audit` query their respective advisory databases.
# Manual/report-only tool — it does not install dependencies or modify anything.

set -uo pipefail

usage() {
  cat <<'EOF'
Usage: audit-packages.sh <path> [--level=<info|low|moderate|high|critical>] [--audit=TYPE[,TYPE...]]

Recursively finds every package manifest under <path>, runs a vulnerability
audit against each one, and reports a short summary per package.

The following directories are never descended into: node_modules, vendor,
dist, build, out, Pods, DerivedData, and any hidden directory (name starting
with a dot, e.g. .git, .next, .gradle, .build, .expo, .cache). A package whose
own directory happens to be named one of these (e.g. packages/build) is
skipped too — rename it or audit that path directly if that's an issue.

Audits require package.json and package-lock.json for npm, or composer.json
and composer.lock for Composer. Packages without a lockfile are skipped and
listed separately. Installed dependencies (node_modules or vendor) are not
required; audits use the lockfile.

Exits 0 if nothing was flagged at --level, 1 if any package was flagged, 2 on
usage error.

Options:
  --level=LEVEL   Only flag packages with vulnerabilities at or above this
                   severity (default: low, i.e. any vulnerability).
  --audit=TYPE     Which audit(s) to run: npm, composer. Comma- or space-separated
                   for more than one, e.g. --audit=npm,composer or
                   --audit="npm composer". Default: npm.
  --no-color       Disable colored/emoji output (also respects the NO_COLOR env var).
  -h, --help       Show this help text.
EOF
}

emoji_for_severity() {
  case "$1" in
    critical) echo "🚨" ;;
    high) echo "🔴" ;;
    moderate) echo "🟠" ;;
    low) echo "🟡" ;;
    info) echo "⚪" ;;
    *) echo "⚪" ;;
  esac
}

color_for_severity() {
  case "$1" in
    critical) printf '%s' "$c_bold_red" ;;
    high) printf '%s' "$c_red" ;;
    moderate) printf '%s' "$c_yellow" ;;
    low) printf '%s' "$c_cyan" ;;
    info) printf '%s' "$c_reset" ;;
    *) printf '%s' "$c_reset" ;;
  esac
}

severity_rank() {
  case "$1" in
    info) echo 0 ;;
    low) echo 1 ;;
    moderate) echo 2 ;;
    high) echo 3 ;;
    critical) echo 4 ;;
    *) echo -1 ;;
  esac
}

root=""
level="low"
no_color=0
audit_types_raw="npm"

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --level=*)
      level="${1#*=}"
      ;;
    --level)
      level="${2:-}"
      shift
      ;;
    --audit=*)
      audit_types_raw="${1#*=}"
      ;;
    --audit)
      audit_types_raw="${2:-}"
      shift
      ;;
    --no-color)
      no_color=1
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [ -n "$root" ]; then
        echo "Unexpected extra argument: $1" >&2
        usage >&2
        exit 2
      fi
      root="$1"
      ;;
  esac
  shift
done

if [ -z "$root" ]; then
  usage >&2
  exit 2
fi

level_rank=$(severity_rank "$level")
if [ "$level_rank" -lt 0 ]; then
  echo "Invalid --level '$level'. Must be one of: info, low, moderate, high, critical." >&2
  exit 2
fi

# Accepts comma- and/or space-separated audit types in a single token.
audit_types=()
IFS=', ' read -ra audit_types_split <<< "$audit_types_raw"
for audit_type in "${audit_types_split[@]}"; do
  case "$audit_type" in
    npm|composer)
      audit_types+=("$audit_type")
      ;;
    *)
      echo "Invalid --audit type '$audit_type'. Must be one of: npm, composer." >&2
      exit 2
      ;;
  esac
done
if [ "${#audit_types[@]}" -eq 0 ]; then
  echo "No valid --audit types given." >&2
  exit 2
fi

use_npm=0
use_composer=0
for audit_type in "${audit_types[@]}"; do
  [ "$audit_type" = "npm" ] && use_npm=1
  [ "$audit_type" = "composer" ] && use_composer=1
done

if [ ! -d "$root" ]; then
  echo "Path not found or not a directory: $root" >&2
  exit 2
fi

if ! command -v node >/dev/null 2>&1; then
  echo "node could not be found, you must install it first!" >&2
  exit 1
fi

if [ "$use_npm" -eq 1 ] && ! command -v npm >/dev/null 2>&1; then
  echo "npm could not be found, you must install it first!" >&2
  exit 1
fi

if [ "$use_composer" -eq 1 ] && ! command -v composer >/dev/null 2>&1; then
  echo "composer could not be found, you must install it first!" >&2
  exit 1
fi

find_manifests() {
  local manifest_name="$1"
  find "$root" \( -type d \( \
      -name node_modules -o \
      -name vendor -o \
      -name dist -o \
      -name build -o \
      -name out -o \
      -name Pods -o \
      -name DerivedData -o \
      -name '.*' \
    \) \) -prune -o -type f -name "$manifest_name" -print | sort
}

# Applies --level filtering/formatting to one audit result and appends it to
# the shared flagged_lines/clean_lines arrays. $counts is "info|low|moderate|high|critical|total".
process_result() {
  local dir="$1" label="$2" counts="$3"
  local info low moderate high critical total

  IFS='|' read -r info low moderate high critical total <<< "$counts"

  local at_or_above=0
  [ "$level_rank" -le 0 ] && at_or_above=$((at_or_above + info))
  [ "$level_rank" -le 1 ] && at_or_above=$((at_or_above + low))
  [ "$level_rank" -le 2 ] && at_or_above=$((at_or_above + moderate))
  [ "$level_rank" -le 3 ] && at_or_above=$((at_or_above + high))
  [ "$level_rank" -le 4 ] && at_or_above=$((at_or_above + critical))

  if [ "$at_or_above" -eq 0 ]; then
    clean_lines+=("✅ ${c_green}[$label] ${dir}${c_reset}")
    return
  fi

  local worst="info"
  [ "$low" -gt 0 ] && worst="low"
  [ "$moderate" -gt 0 ] && worst="moderate"
  [ "$high" -gt 0 ] && worst="high"
  [ "$critical" -gt 0 ] && worst="critical"

  local breakdown=""
  [ "$info" -gt 0 ] && breakdown="${breakdown}${breakdown:+, }${info} info"
  [ "$low" -gt 0 ] && breakdown="${breakdown}${breakdown:+, }$(color_for_severity low)${low} low${c_reset}"
  [ "$moderate" -gt 0 ] && breakdown="${breakdown}${breakdown:+, }$(color_for_severity moderate)${moderate} moderate${c_reset}"
  [ "$high" -gt 0 ] && breakdown="${breakdown}${breakdown:+, }$(color_for_severity high)${high} high${c_reset}"
  [ "$critical" -gt 0 ] && breakdown="${breakdown}${breakdown:+, }$(color_for_severity critical)${critical} critical${c_reset}"

  local emoji path_color
  emoji=$(emoji_for_severity "$worst")
  path_color=$(color_for_severity "$worst")

  flagged_lines+=("${emoji} ${path_color}[$label] ${dir}: ${total} vulnerabilities${c_reset} (${breakdown})")
}

if [ "$no_color" -eq 0 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  c_reset=$'\033[0m'
  c_bold=$'\033[1m'
  c_red=$'\033[0;31m'
  c_bold_red=$'\033[1;31m'
  c_yellow=$'\033[0;33m'
  c_cyan=$'\033[0;36m'
  c_green=$'\033[0;32m'
else
  c_reset="" c_bold="" c_red="" c_bold_red="" c_yellow="" c_cyan="" c_green=""
fi

flagged_lines=()
skipped_lines=()
error_lines=()
clean_lines=()
scanned_count=0

if [ "$use_npm" -eq 1 ]; then
  while IFS= read -r file; do
    dir=$(dirname "$file")
    echo "Auditing (npm) $dir..." >&2
    scanned_count=$((scanned_count + 1))

    if [ ! -f "$dir/package-lock.json" ]; then
      skipped_lines+=("[npm] $dir: no package-lock.json")
      continue
    fi

    audit_json=$(npm audit --json --package-lock-only --prefix "$dir" 2>/dev/null)

    counts=$(printf '%s' "$audit_json" | node -e '
      let raw = "";
      process.stdin.on("data", (chunk) => { raw += chunk; });
      process.stdin.on("end", () => {
        const data = JSON.parse(raw);
        const v = data.metadata && data.metadata.vulnerabilities;
        if (!v) {
          throw new Error("no vulnerability metadata in npm audit output");
        }
        const pick = (key) => v[key] || 0;
        console.log([pick("info"), pick("low"), pick("moderate"), pick("high"), pick("critical"), pick("total")].join("|"));
      });
    ' 2>/dev/null)

    if [ -z "$counts" ]; then
      error_lines+=("[npm] $dir: npm audit failed or returned unexpected output")
      continue
    fi

    process_result "$dir" npm "$counts"
  done < <(find_manifests package.json)
fi

if [ "$use_composer" -eq 1 ]; then
  while IFS= read -r file; do
    dir=$(dirname "$file")
    echo "Auditing (composer) $dir..." >&2
    scanned_count=$((scanned_count + 1))

    if [ ! -f "$dir/composer.lock" ]; then
      skipped_lines+=("[composer] $dir: (composer.lock not found)")
      continue
    fi

    audit_json=$(composer audit --format=json --locked --no-interaction -d "$dir" 2>/dev/null)

    counts=$(printf '%s' "$audit_json" | node -e '
      let raw = "";
      process.stdin.on("data", (chunk) => { raw += chunk; });
      process.stdin.on("end", () => {
        const data = JSON.parse(raw);
        const advisories = data.advisories;
        if (!advisories) {
          throw new Error("no advisories field in composer audit output");
        }
        const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
        let total = 0;
        for (const pkg in advisories) {
          for (const advisory of advisories[pkg]) {
            total++;
            let sev = String(advisory.severity || "low").toLowerCase();
            if (sev === "medium") sev = "moderate";
            if (!(sev in counts)) sev = "low";
            counts[sev]++;
          }
        }
        console.log([counts.info, counts.low, counts.moderate, counts.high, counts.critical, total].join("|"));
      });
    ' 2>/dev/null)

    if [ -z "$counts" ]; then
      error_lines+=("[composer] $dir: composer audit failed or returned unexpected output")
      continue
    fi

    process_result "$dir" composer "$counts"
  done < <(find_manifests composer.json)
fi

if [ "$scanned_count" -eq 0 ]; then
  echo "No package manifests found under $root for audit type(s): ${audit_types[*]}"
  exit 0
fi

if [ "${#clean_lines[@]}" -gt 0 ]; then
  echo
  echo "${c_bold}Clean packages:${c_reset}"
  printf '  %s\n' "${clean_lines[@]}"
fi

if [ "${#skipped_lines[@]}" -gt 0 ]; then
  echo
  echo "${c_yellow}Skipped:${c_reset}"
  printf '  %s\n' "${skipped_lines[@]}"
fi

if [ "${#error_lines[@]}" -gt 0 ]; then
  echo
  echo "${c_red}Errors (audit failed):${c_reset}"
  printf '  %s\n' "${error_lines[@]}"
fi

echo
if [ "${#flagged_lines[@]}" -gt 0 ]; then
  echo "${c_bold}Vulnerable packages:${c_reset}"
  printf '  %s\n' "${flagged_lines[@]}"
else
  echo "${c_green}✅ No packages flagged at --level=$level.${c_reset}"
fi

echo
flagged_color="$c_green"
[ "${#flagged_lines[@]}" -gt 0 ] && flagged_color="$c_bold_red"
echo "Scanned $scanned_count package(s): ${flagged_color}${#flagged_lines[@]} flagged${c_reset}, ${c_green}${#clean_lines[@]} clean${c_reset}, ${#skipped_lines[@]} skipped, ${#error_lines[@]} errors."

[ "${#flagged_lines[@]}" -gt 0 ] && exit 1
exit 0
