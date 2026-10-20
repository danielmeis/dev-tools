#!/bin/bash
# Recursively finds every package manifest under a given path (skipping
# node_modules, vendor, build output, and native build/dependency dirs) and
# reports vulnerability audit results per package.
#
# Usage:
#   ./audit-packages.sh <path> [--level=<info|low|moderate|high|critical>] [--audit=TYPE[,TYPE...]] [--epss[=THRESHOLD]] [--epss-all] [--no-epss]
#
# Examples:
#   ./audit-packages.sh ../../my-project
#   ./audit-packages.sh ../../my-project/wp-content/plugins/my-plugin
#   ./audit-packages.sh ../../my-project --level=high
#   ./audit-packages.sh ../../my-project --audit=composer
#   ./audit-packages.sh ../../my-project --audit=npm,composer
#   ./audit-packages.sh ../../my-project --epss=0.05
#   ./audit-packages.sh ../../my-project --epss-all
#   ./audit-packages.sh ../../my-project --no-epss
#
# Requirements: bash, node 18+ on PATH always; npm and/or composer on PATH depending
# on which --audit types are selected. Network access is required since both
# `npm audit` and `composer audit` query their respective advisory databases.
# Manual/report-only tool — it does not install dependencies or modify anything.

set -uo pipefail

usage() {
  cat <<'EOF'
Usage: audit-packages.sh <path> [--level=<info|low|moderate|high|critical>] [--audit=TYPE[,TYPE...]] [--epss[=THRESHOLD]] [--epss-all] [--no-epss]

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
  --epss[=N]       EPSS section in the summary (on by default): look up the exploit
                   probability (0-1) of each unique high/critical advisory and
                   list those at or above N (default 0.01, i.e. 1%). Uses the
                   public OSV.dev and FIRST.org APIs. Advisories without a CVE
                   or EPSS score are counted as unscored, not dropped.
  --epss-all       List every matching EPSS advisory and all of its paths instead
                   of the top 10 (and 5 paths each). No extra lookups.
  --no-epss        Skip the EPSS lookup and section (no network calls beyond the audits).
  --no-color       Disable colors (also respects the NO_COLOR env var); emoji are still printed.
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
use_epss=1
epss_threshold="0.01"
epss_limit=10
epss_path_limit=5

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
    --epss)
      use_epss=1
      ;;
    --epss=*)
      use_epss=1
      epss_threshold="${1#*=}"
      ;;
    --epss-all)
      epss_limit=999999
      epss_path_limit=999999
      ;;
    --no-epss)
      use_epss=0
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

if [ "$use_epss" -eq 1 ] && ! awk -v t="$epss_threshold" 'BEGIN { exit !(t ~ /^[0-9]*\.?[0-9]+$/ && t + 0 >= 0 && t + 0 <= 1) }'; then
  echo "Invalid --epss threshold '$epss_threshold'. Must be a number between 0 and 1." >&2
  exit 2
fi

if [ ! -d "$root" ]; then
  echo "Path not found or not a directory: $root" >&2
  exit 2
fi

if ! command -v node >/dev/null 2>&1; then
  echo "node could not be found, you must install it first!" >&2
  exit 1
fi

if [ "$use_epss" -eq 1 ] && ! node -e 'process.exit(typeof fetch === "function" ? 0 : 1)' 2>/dev/null; then
  echo "--epss requires node 18+ (global fetch)." >&2
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
  find "$root" -mindepth 1 \( -type d \( \
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
# $advisories is optional newline-separated "severity|package|id|cve|scope" rows (high/critical only).
process_result() {
  local dir="$1" label="$2" counts="$3" advisories="${4:-}"
  local adv_line
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

  if [ "$critical" -gt 0 ]; then
    total_critical=$((total_critical + critical))
    pkgs_critical=$((pkgs_critical + 1))
  fi
  if [ "$level_rank" -le 3 ] && [ "$high" -gt 0 ]; then
    total_high=$((total_high + high))
    pkgs_high=$((pkgs_high + 1))
  fi

  if [ "$use_epss" -eq 1 ] && [ -n "$advisories" ]; then
    while IFS= read -r adv_line; do
      [ -z "$adv_line" ] && continue
      if [ "${adv_line%%|*}" = "critical" ] || [ "$level_rank" -le 3 ]; then
        epss_advisories+=("${adv_line}|${dir}")
      fi
    done <<< "$advisories"
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
  c_dim=$'\033[2m'
  c_red=$'\033[0;31m'
  c_bold_red=$'\033[1;31m'
  c_yellow=$'\033[0;33m'
  c_cyan=$'\033[0;36m'
  c_green=$'\033[0;32m'
else
  c_reset="" c_bold="" c_dim="" c_red="" c_bold_red="" c_yellow="" c_cyan="" c_green=""
fi

flagged_lines=()
skipped_lines=()
error_lines=()
clean_lines=()
scanned_count=0
total_critical=0
total_high=0
pkgs_critical=0
pkgs_high=0
epss_advisories=()

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

    # Line 1: counts. Remaining lines: "severity|package|GHSA-id|cve|scope" per high/critical advisory.
    audit_out=$(printf '%s' "$audit_json" | node -e '
      const fs = require("fs");
      const path = require("path");
      let raw = "";
      process.stdin.on("data", (chunk) => { raw += chunk; });
      process.stdin.on("end", () => {
        const data = JSON.parse(raw);
        const v = data.metadata && data.metadata.vulnerabilities;
        if (!v) {
          throw new Error("no vulnerability metadata in npm audit output");
        }
        let lockPkgs = {};
        try {
          lockPkgs = JSON.parse(fs.readFileSync(path.join(process.argv[1], "package-lock.json"), "utf8")).packages || {};
        } catch (e) { /* lockfile v1 or unreadable: treat everything as prod */ }
        const scopeOf = (name) => {
          const nodes = ((data.vulnerabilities || {})[name] || {}).nodes || [];
          return nodes.length > 0 && nodes.every((n) => lockPkgs[n] && lockPkgs[n].dev === true) ? "dev" : "prod";
        };
        const pick = (key) => v[key] || 0;
        const out = [[pick("info"), pick("low"), pick("moderate"), pick("high"), pick("critical"), pick("total")].join("|")];
        const seen = new Set();
        for (const [name, vuln] of Object.entries(data.vulnerabilities || {})) {
          for (const via of vuln.via || []) {
            if (typeof via !== "object" || (via.severity !== "high" && via.severity !== "critical")) continue;
            const m = /GHSA-[\w-]+/.exec(via.url || "");
            const id = m ? m[0] : String(via.source);
            if (seen.has(id)) continue;
            seen.add(id);
            out.push([via.severity, via.name || name, id, "", scopeOf(via.name || name)].join("|"));
          }
        }
        console.log(out.join("\n"));
      });
    ' "$dir" 2>/dev/null)

    counts="${audit_out%%$'\n'*}"
    advisories=""
    [[ "$audit_out" == *$'\n'* ]] && advisories="${audit_out#*$'\n'}"

    if [ -z "$counts" ]; then
      error_lines+=("[npm] $dir: npm audit failed or returned unexpected output")
      continue
    fi

    process_result "$dir" npm "$counts" "$advisories"
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

    # Line 1: counts. Remaining lines: "severity|package|id|cve|scope" per high/critical advisory.
    audit_out=$(printf '%s' "$audit_json" | node -e '
      const fs = require("fs");
      const path = require("path");
      let raw = "";
      process.stdin.on("data", (chunk) => { raw += chunk; });
      process.stdin.on("end", () => {
        const data = JSON.parse(raw);
        const advisories = data.advisories;
        if (!advisories) {
          throw new Error("no advisories field in composer audit output");
        }
        const prodNames = new Set();
        const devNames = new Set();
        try {
          const lock = JSON.parse(fs.readFileSync(path.join(process.argv[1], "composer.lock"), "utf8"));
          (lock.packages || []).forEach((p) => prodNames.add(String(p.name).toLowerCase()));
          (lock["packages-dev"] || []).forEach((p) => devNames.add(String(p.name).toLowerCase()));
        } catch (e) { /* unreadable lock: treat everything as prod */ }
        const scopeOf = (name) => {
          const n = String(name).toLowerCase();
          return devNames.has(n) && !prodNames.has(n) ? "dev" : "prod";
        };
        const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
        const rows = [];
        let total = 0;
        for (const pkg in advisories) {
          for (const advisory of advisories[pkg]) {
            total++;
            let sev = String(advisory.severity || "low").toLowerCase();
            if (sev === "medium") sev = "moderate";
            if (!(sev in counts)) sev = "low";
            counts[sev]++;
            if (sev === "high" || sev === "critical") {
              const ghsa = (advisory.sources || []).map((s) => s.remoteId).find((r) => /^GHSA-/.test(r || ""));
              const id = ghsa || advisory.cve || advisory.advisoryId || "unknown";
              rows.push([sev, advisory.packageName || pkg, id, advisory.cve || "", scopeOf(advisory.packageName || pkg)].join("|"));
            }
          }
        }
        console.log([[counts.info, counts.low, counts.moderate, counts.high, counts.critical, total].join("|"), ...rows].join("\n"));
      });
    ' "$dir" 2>/dev/null)

    counts="${audit_out%%$'\n'*}"
    advisories=""
    [[ "$audit_out" == *$'\n'* ]] && advisories="${audit_out#*$'\n'}"

    if [ -z "$counts" ]; then
      error_lines+=("[composer] $dir: composer audit failed or returned unexpected output")
      continue
    fi

    process_result "$dir" composer "$counts" "$advisories"
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

if [ $((total_critical + total_high)) -gt 0 ]; then
  echo
  echo "${c_bold}📊 High/Critical totals across ${#flagged_lines[@]} flagged package(s):${c_reset}"
  if [ "$total_critical" -gt 0 ]; then
    printf '  %s %s%-9s %6d%s  (in %d package(s))\n' "$(emoji_for_severity critical)" "$(color_for_severity critical)" "Critical" "$total_critical" "$c_reset" "$pkgs_critical"
  fi
  if [ "$total_high" -gt 0 ]; then
    printf '  %s %s%-9s %6d%s  (in %d package(s))\n' "$(emoji_for_severity high)" "$(color_for_severity high)" "High" "$total_high" "$c_reset" "$pkgs_high"
  fi
  printf '  🧮 %-9s %6d\n' "Combined" "$((total_critical + total_high))"
  [ "$use_epss" -eq 1 ] && echo "  ${c_dim}Counts are vulnerable packages per audit; the EPSS section below counts unique advisories.${c_reset}"
fi

if [ "$use_epss" -eq 1 ] && [ "${#epss_advisories[@]}" -gt 0 ]; then
  echo "Looking up EPSS scores for ${#epss_advisories[@]} advisory row(s)..." >&2
  # Output: "unique|scored|matched|failed|prodMatched|devMatched" header, then "epss%|severity|package|id|cve|scope|dir,dir,..." per match, highest first within each scope. Dirs are separated by \x1f.
  epss_out=$(printf '%s\n' "${epss_advisories[@]}" | node -e '
    const threshold = parseFloat(process.argv[1]);
    let raw = "";
    process.stdin.on("data", (chunk) => { raw += chunk; });
    process.stdin.on("end", async () => {
      const byId = new Map();
      for (const line of raw.split("\n")) {
        if (!line) continue;
        const [sev, pkg, id, cve, scope, ...dirParts] = line.split("|");
        const dir = dirParts.join("|");
        if (!byId.has(id)) byId.set(id, { sev, pkg, id, cve, scope, dirs: new Set() });
        const entry = byId.get(id);
        if (scope === "prod") entry.scope = "prod";
        entry.dirs.add(dir);
      }
      const items = [...byId.values()];
      for (const it of items) {
        if (it.cve && !/^CVE-\d{4}-\d{4,}$/.test(it.cve)) it.cve = "";
      }
      const getJson = async (url) => {
        const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
        if (!res.ok) throw new Error(String(res.status));
        return res.json();
      };

      const needCve = items.filter((i) => !i.cve && /^GHSA-/.test(i.id));
      for (let i = 0; i < needCve.length; i += 10) {
        await Promise.all(needCve.slice(i, i + 10).map(async (it) => {
          try {
            const v = await getJson("https://api.osv.dev/v1/vulns/" + encodeURIComponent(it.id));
            const alias = (v.aliases || []).find((a) => /^CVE-\d{4}-\d{4,}$/.test(a));
            if (alias) it.cve = alias;
          } catch (e) { /* unresolved advisories are reported as unscored */ }
        }));
      }

      const cves = [...new Set(items.map((i) => i.cve).filter(Boolean))];
      const scores = new Map();
      let failed = 0;
      for (let i = 0; i < cves.length; i += 50) {
        try {
          const d = await getJson("https://api.first.org/data/v1/epss?cve=" + cves.slice(i, i + 50).join(","));
          for (const r of d.data || []) scores.set(r.cve, parseFloat(r.epss));
        } catch (e) { failed = 1; }
      }

      const scored = items.filter((i) => scores.has(i.cve));
      const matched = scored.filter((i) => scores.get(i.cve) >= threshold)
        .sort((a, b) => ((a.scope === "dev") - (b.scope === "dev")) || (scores.get(b.cve) - scores.get(a.cve)));
      const devMatched = matched.filter((i) => i.scope === "dev").length;
      console.log([items.length, scored.length, matched.length, failed, matched.length - devMatched, devMatched].join("|"));
      for (const i of matched) {
        console.log([(scores.get(i.cve) * 100).toFixed(1), i.sev, i.pkg, i.id, i.cve, i.scope === "dev" ? "dev-only" : "prod", [...i.dirs].sort().join("\x1f")].join("|"));
      }
    });
  ' "$epss_threshold" 2>/dev/null)

  echo
  if [ -z "$epss_out" ]; then
    echo "${c_yellow}⚠️  EPSS lookup failed (network or API error); skipped.${c_reset}"
  else
    IFS='|' read -r e_total e_scored e_matched e_failed e_prod e_dev <<< "${epss_out%%$'\n'*}"
    e_pct=$(awk -v t="$epss_threshold" 'BEGIN { printf "%g", t * 100 }')
    echo "${c_bold}🎯 EPSS ≥ ${e_pct}% (most likely to be exploited), of ${e_total} unique high/critical advisories:${c_reset}"
    if [ "$e_matched" -gt 0 ]; then
      e_split="${e_prod} prod, ${e_dev} dev-only"
      [ "$e_prod" -gt 0 ] && e_split="${c_bold_red}🚩 ${e_prod} prod${c_reset}, ${e_dev} dev-only"
      echo "  ${c_bold_red}${e_matched} advisories — fix these first${c_reset} (${e_split})"
      e_shown=0
      while IFS='|' read -r e_score e_sev e_pkg e_id e_cve e_scope e_dirs; do
        [ "$e_shown" -ge "$epss_limit" ] && break
        e_scope_label="$e_scope"
        e_scope_color="$c_dim"
        if [ "$e_scope" = "prod" ]; then
          e_scope_label="🚩 PROD "
          e_scope_color="$c_bold_red"
        fi
        printf '    %s %-8s %-30s %-16s %5s%%  %s%s%s (%s)\n' "$(emoji_for_severity "$e_sev")" "$e_sev" "$e_pkg" "$e_cve" "$e_score" "$e_scope_color" "$e_scope_label" "$c_reset" "$e_id"
        IFS=$'\x1f' read -ra e_dir_list <<< "$e_dirs"
        for e_dir in "${e_dir_list[@]:0:epss_path_limit}"; do
          echo "        ↳ $e_dir"
        done
        [ "${#e_dir_list[@]}" -gt "$epss_path_limit" ] && echo "        ↳ ... and $((${#e_dir_list[@]} - epss_path_limit)) more path(s)"
        e_shown=$((e_shown + 1))
      done < <(printf '%s\n' "${epss_out#*$'\n'}")
      [ "$e_matched" -gt "$epss_limit" ] && echo "    ... and $((e_matched - epss_limit)) more (use --epss-all to show everything)"
      [ "$e_dev" -gt 0 ] && echo "  dev-only = lockfile says devDependencies only; it can still ship if your CI/deploy installs dev packages or bundles them into client code."
    else
      echo "  ${c_green}None at or above the threshold.${c_reset}"
    fi
    echo "  ${e_scored} scored, $((e_total - e_scored)) unscored (no CVE or not yet in EPSS) — unscored advisories are not safe, just unranked."
    [ "$e_failed" = "1" ] && echo "  ${c_yellow}⚠️  Some EPSS batches failed; results may be incomplete.${c_reset}"
  fi
fi

[ "${#flagged_lines[@]}" -gt 0 ] && exit 1
exit 0
