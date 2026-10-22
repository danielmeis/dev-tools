#!/bin/bash
# Recursively finds every package manifest under a given path (skipping
# node_modules, vendor, build output, and native build/dependency dirs) and
# reports vulnerability audit results per package.
#
# Usage: ./audit-packages.sh <path> [options]   (run with --help for every option)
#
# Examples:
#   ./audit-packages.sh ../../my-project
#   ./audit-packages.sh ../../my-project/wp-content/plugins/my-plugin
#   ./audit-packages.sh ../../my-project --level=high
#   ./audit-packages.sh ../../my-project --audit=npm,composer
#   ./audit-packages.sh ../../my-project --epss=0.05 --check-remote
#
# Requirements: bash and node 18+ on PATH; npm and/or composer depending on --audit; git
# for the repo check (skipped if missing). Network access is required: the audits query the
# npm/Packagist advisory databases, and EPSS queries OSV.dev and FIRST.org (see --no-epss).
# Manual/report-only tool: it does not install dependencies or modify anything.
# Keep the lib/ directory (node helpers) next to this script.

# No -e on purpose: many checks are written as `[ ... ] && ...` and a failing test must not abort.
set -uo pipefail

# Resolve lib/ next to this script, following symlinks.
script_path="${BASH_SOURCE[0]}"
while [ -L "$script_path" ]; do
  link_dir=$(cd "$(dirname "$script_path")" && pwd)
  script_path=$(readlink "$script_path")
  case "$script_path" in
    /*) ;;
    *) script_path="$link_dir/$script_path" ;;
  esac
done
lib_dir="$(cd "$(dirname "$script_path")" && pwd)/lib"

# Stop any in-flight audit and clear the progress line on exit or interrupt.
# shellcheck disable=SC2329 # invoked through the traps below
cleanup() {
  pkill -P $$ 2>/dev/null
  [ -t 2 ] && printf '\r\033[2K' >&2
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
  cat <<'EOF'
Usage: audit-packages.sh <path> [--level=<info|low|moderate|high|critical>] [--audit=TYPE[,TYPE...]] [--epss[=THRESHOLD]] [--epss-all] [--no-epss] [--no-git-check] [--check-remote] [--require-default-branch] [--yes] [--timeout=SECONDS]

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
usage error, 3 if you decline the repo-state prompt or --require-default-branch
is set and a repo needs attention, 4 if an audit failed or timed out. Codes 3
and 4 apply only when no vulnerabilities were flagged (1 wins).

Before auditing, every git repo containing a scanned manifest is checked
read-only: current branch vs. the default branch, uncommitted changes, and
ahead/behind counts. Nothing is checked out, fetched, or modified. If any repo
needs attention and stdin is a terminal, you are asked whether to continue.

Options:
  --level=LEVEL    Only flag packages with vulnerabilities at or above this
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
  --no-git-check   Skip the read-only repo state check.
  --check-remote   In the repo check, ask each remote for its current default-branch
                   commit (git ls-remote: read-only, needs network) instead of
                   trusting local remote refs, which may be stale.
  --require-default-branch
                   Exit 3 if any repo is off its default branch, has uncommitted
                   changes, or is behind/ahead of it.
  -y, --yes        Don't ask to continue when repos need attention.
  --timeout=SECS   Give up on a single npm/composer audit after SECS seconds and
                   report it as an error (default: 90, 0 = no limit). While a
                   command runs longer than 3s, the progress line shows the
                   elapsed time so a stall is visible.
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
git_check=1
check_remote=0
require_default=0
assume_yes=0
audit_timeout=90
remote_timeout=15
progress_base=""
progress_prefix=""
progress_name=""
term_cols=80
if [ -t 2 ]; then
  term_cols=$(tput cols 2>/dev/null)
  [[ "$term_cols" =~ ^[0-9]+$ ]] || term_cols=80
fi

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
    --no-git-check)
      git_check=0
      ;;
    --check-remote)
      check_remote=1
      ;;
    --require-default-branch)
      require_default=1
      ;;
    -y|--yes)
      assume_yes=1
      ;;
    --timeout=*)
      audit_timeout="${1#*=}"
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
# The ${arr[@]+...} form keeps bash 3.2 from failing on an empty array under set -u.
for audit_type in ${audit_types_split[@]+"${audit_types_split[@]}"}; do
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

if ! [[ "$audit_timeout" =~ ^[0-9]+$ ]]; then
  echo "Invalid --timeout '$audit_timeout'. Must be a whole number of seconds (0 = no limit)." >&2
  exit 2
fi

if ! command -v node >/dev/null 2>&1; then
  echo "node could not be found, you must install it first!" >&2
  exit 1
fi

for lib_file in npm-audit.js composer-audit.js epss.js; do
  if [ ! -f "$lib_dir/$lib_file" ]; then
    echo "Missing $lib_dir/$lib_file; keep the lib/ directory next to audit-packages.sh." >&2
    exit 1
  fi
done

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

if [ "$git_check" -eq 1 ] && ! command -v git >/dev/null 2>&1; then
  echo "git could not be found; skipping the repo state check." >&2
  git_check=0
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

# Read-only git access. GIT_OPTIONAL_LOCKS=0 stops `git status` from refreshing the index, and
# core.fsmonitor=false keeps a repo or global fsmonitor setting from starting a daemon or program.
git_ro() {
  GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 git -c core.fsmonitor=false -C "$repo_root" "$@" </dev/null
}

file_mtime() {
  stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null
}

# Prints "<manifest count> <repo root>" for every git repo containing a scanned manifest.
repo_roots_with_counts() {
  local file
  {
    [ "$use_npm" -eq 1 ] && find_manifests package.json
    [ "$use_composer" -eq 1 ] && find_manifests composer.json
  } | while IFS= read -r file; do
    GIT_OPTIONAL_LOCKS=0 git -C "$(dirname "$file")" rev-parse --show-toplevel 2>/dev/null
  done | sort | uniq -c
}

# Builds progress_base from progress_prefix + progress_name. A path too long for the terminal is
# trimmed from the left at a "/" boundary; $1 reserves columns for a suffix (the stall timer).
build_progress() {
  local reserve="${1:-0}" name="$progress_name" budget tail
  budget=$((term_cols - ${#progress_prefix} - reserve - 1))
  [ "$budget" -lt 12 ] && budget=12
  if [ "${#name}" -gt "$budget" ]; then
    # ${name: -N} is empty when N exceeds the length, hence the length check above.
    tail="${name: -$((budget - 2))}"
    case "$tail" in
      */*) name="…/${tail#*/}" ;;
      *) name="…${tail}" ;;
    esac
  fi
  progress_base="${progress_prefix}${name}"
}

# Single-line "[####------] 5/14  label  path" counter on stderr (terminal only); progress_base is
# kept so run_limited can append an elapsed-time warning to the same line.
show_progress() {
  local done_count="$1" total="$2" name="$3" label="${4:-}" width=12 filled bar
  filled=$(( done_count * width / total ))
  bar="$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' "$((width - filled))" '' | tr ' ' '-')"
  progress_prefix="$(printf '  [%s] %d/%d  ' "$bar" "$((done_count + 1))" "$total")${label:+${label}  }"
  progress_name="$name"
  build_progress 0
  [ -t 2 ] && printf '\r\033[2K%s' "$progress_base" >&2
  return 0
}

# Runs a command with a time limit (0 = none); stderr is discarded. After 3s the progress
# line gains an elapsed-time warning so a stall is visible. Returns 124 on timeout.
run_limited() {
  local limit="$1" pid elapsed start="$SECONDS" shown=0 rc suffix
  shift
  "$@" 2>/dev/null &
  pid=$!
  # Background jobs ignore Ctrl-C, so stop the command ourselves when this subshell is signalled.
  trap 'kill "$pid" 2>/dev/null; exit 130' INT TERM
  while kill -0 "$pid" 2>/dev/null; do
    elapsed=$((SECONDS - start))
    if [ "$limit" -gt 0 ] && [ "$elapsed" -ge "$limit" ]; then
      pkill -P "$pid" 2>/dev/null
      kill "$pid" 2>/dev/null
      { wait "$pid"; } 2>/dev/null
      if [ "$shown" -eq 1 ] && [ -t 2 ]; then
        build_progress 0
        printf '\r\033[2K%s' "$progress_base" >&2
      fi
      return 124
    fi
    if [ "$elapsed" -ge 3 ] && [ -t 2 ]; then
      suffix="⏳ ${elapsed}s"
      [ "$limit" -gt 0 ] && suffix="${suffix} (limit ${limit}s)"
      build_progress $((${#suffix} + 4))
      printf '\r\033[2K%s  %s%s%s' "$progress_base" "$c_yellow" "$suffix" "$c_reset" >&2
      shown=1
    fi
    sleep 0.2
  done
  wait "$pid"
  rc=$?
  if [ "$shown" -eq 1 ] && [ -t 2 ]; then
    build_progress 0
    printf '\r\033[2K%s' "$progress_base" >&2
  fi
  return "$rc"
}

# Audit-phase counter; plain log lines when stderr isn't a terminal.
audit_progress() {
  if [ -t 2 ]; then
    show_progress "$audit_done" "$audit_total" "$2" "$1"
  else
    echo "Auditing ($1) $2..." >&2
  fi
  audit_done=$((audit_done + 1))
}

# Appends to repo_issue_lines/repo_attention/repo_ok/repo_stale. Never writes to the repo.
check_repo() {
  repo_root="$1"
  local count="$2"
  local branch default_ref="" default_name="" cand compare="" remote_sha="" local_sha ssh_cmd
  local ahead="" behind="" fetch_file mtime age st dirty issues="" stale=0

  branch=$(git_ro symbolic-ref --quiet --short HEAD 2>/dev/null)
  default_ref=$(git_ro symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null)
  if [ -z "$default_ref" ]; then
    for cand in origin/main origin/master; do
      if git_ro rev-parse --verify --quiet "refs/remotes/$cand" >/dev/null 2>&1; then
        default_ref="$cand"
        break
      fi
    done
  fi
  default_name="${default_ref#origin/}"

  if [ -z "$branch" ]; then
    issues="detached HEAD at $(git_ro rev-parse --short HEAD 2>/dev/null)"
  elif [ -n "$default_name" ]; then
    if [ "$branch" != "$default_name" ]; then
      issues="on '$branch' (default is '$default_name')"
    fi
  elif [ "$branch" != "main" ] && [ "$branch" != "master" ]; then
    issues="on '$branch' (default branch unknown: no origin remote)"
  fi

  if [ -n "$default_ref" ]; then
    compare="refs/remotes/$default_ref"
    if [ "$check_remote" -eq 1 ]; then
      # ssh would otherwise prompt on /dev/tty for passphrases and host keys; fail fast instead.
      ssh_cmd="${GIT_SSH_COMMAND:-}"
      if [ -z "$ssh_cmd" ] && [ -z "$(git_ro config --get core.sshCommand 2>/dev/null)" ]; then
        ssh_cmd="ssh -o BatchMode=yes"
      fi
      remote_sha=$(
        [ -n "$ssh_cmd" ] && export GIT_SSH_COMMAND="$ssh_cmd"
        run_limited "$remote_timeout" git_ro ls-remote origin "refs/heads/$default_name" | cut -f1
      )
      if [ -n "$remote_sha" ]; then
        local_sha=$(git_ro rev-parse "$compare" 2>/dev/null)
        if [ "$remote_sha" != "$local_sha" ]; then
          if git_ro cat-file -e "${remote_sha}^{commit}" 2>/dev/null; then
            compare="$remote_sha"
          else
            issues="${issues}${issues:+; }'$default_name' has newer commits on the remote than are fetched locally"
            compare=""
          fi
        fi
      fi
    fi

    if [ -n "$compare" ]; then
      read -r ahead behind < <(git_ro rev-list --left-right --count "HEAD...$compare" 2>/dev/null)
      [ "${behind:-0}" -gt 0 ] && issues="${issues}${issues:+; }${behind} behind ${default_ref}"
      [ "${ahead:-0}" -gt 0 ] && issues="${issues}${issues:+; }${ahead} ahead of ${default_ref} (unpushed)"
    fi

    # Without a live remote check, ahead/behind is only as fresh as the last fetch.
    if [ "$check_remote" -eq 0 ] || [ -z "$remote_sha" ]; then
      fetch_file=$(git_ro rev-parse --git-path FETCH_HEAD 2>/dev/null)
      case "$fetch_file" in
        /*) ;;
        *) fetch_file="$repo_root/$fetch_file" ;;
      esac
      mtime=$(file_mtime "$fetch_file")
      if [ -z "$mtime" ]; then
        stale=1
      else
        age=$(( ($(date +%s) - mtime) / 86400 ))
        [ "$age" -ge 1 ] && stale=1
      fi
    fi
  fi

  st=$(git_ro status --porcelain --untracked-files=no 2>/dev/null)
  if [ -n "$st" ]; then
    dirty="$(printf '%s\n' "$st" | wc -l | tr -d ' ') file(s) with uncommitted changes"
    if printf '%s\n' "$st" | grep -Eq '(package(-lock)?\.json|composer\.(json|lock))$'; then
      dirty="${dirty}, including a manifest/lockfile"
    fi
    issues="${issues}${issues:+; }${dirty}"
  fi

  [ "$stale" -eq 1 ] && repo_stale=$((repo_stale + 1))
  if [ -n "$issues" ]; then
    repo_attention=$((repo_attention + 1))
    repo_issue_lines+=("⚠️  ${c_yellow}${repo_root}${c_reset} — ${issues} (${count} manifest(s) audited)")
  else
    repo_ok=$((repo_ok + 1))
  fi
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
repo_issue_lines=()
repo_attention=0
repo_ok=0
repo_stale=0
repo_root=""

audit_total=0
audit_done=0
[ "$use_npm" -eq 1 ] && audit_total=$((audit_total + $(find_manifests package.json | wc -l)))
[ "$use_composer" -eq 1 ] && audit_total=$((audit_total + $(find_manifests composer.json | wc -l)))

if [ "$git_check" -eq 1 ]; then
  echo "Finding git repos..." >&2
  repo_counts=()
  repo_paths=()
  while read -r repo_count repo_path; do
    [ -z "$repo_path" ] && continue
    repo_counts+=("$repo_count")
    repo_paths+=("$repo_path")
  done < <(repo_roots_with_counts)

  repo_total=${#repo_paths[@]}
  echo "Checking state of ${repo_total} repo(s) (read-only)..." >&2
  repo_index=0
  while [ "$repo_index" -lt "$repo_total" ]; do
    show_progress "$repo_index" "$repo_total" "${repo_paths[$repo_index]}"
    check_repo "${repo_paths[$repo_index]}" "${repo_counts[$repo_index]}"
    repo_index=$((repo_index + 1))
  done
  [ -t 2 ] && printf '\r\033[2K' >&2

  repo_total=$((repo_attention + repo_ok))
  if [ "$repo_total" -gt 0 ]; then
    echo
    echo "${c_bold}🌿 Repo state (${repo_total} repo(s)):${c_reset}"
    if [ "$repo_attention" -gt 0 ]; then
      printf '  %s\n' "${repo_issue_lines[@]}"
      echo
      echo "  Audits reflect each repo's current checkout, so results for these may not match its default branch."
    else
      echo "  ${c_green}✅ All on their default branch, clean, and in sync with local remote refs.${c_reset}"
    fi
    if [ "$repo_stale" -gt 0 ]; then
      echo "  ${repo_stale} repo(s) have remote refs last fetched over a day ago (or never); behind/ahead may be out of date. Use --check-remote for a live check."
    fi
    echo
  fi

  # Only prompt when a human is at the terminal; pipes and CI proceed without blocking.
  if [ "$repo_attention" -gt 0 ] && [ "$assume_yes" -eq 0 ] && [ -t 0 ]; then
    read -r -p "Continue with the audit anyway? [y/N] " reply
    case "$reply" in
      y|Y|yes|YES|Yes) echo ;;
      *) echo "Aborted before auditing." >&2; exit 3 ;;
    esac
  fi
fi

if [ "$use_npm" -eq 1 ]; then
  while IFS= read -r file; do
    dir=$(dirname "$file")
    audit_progress npm "$dir"
    scanned_count=$((scanned_count + 1))

    if [ ! -f "$dir/package-lock.json" ]; then
      skipped_lines+=("[npm] $dir: no package-lock.json")
      continue
    fi

    audit_json=$(run_limited "$audit_timeout" npm audit --json --package-lock-only --prefix "$dir")
    if [ $? -eq 124 ]; then
      error_lines+=("[npm] $dir: timed out after ${audit_timeout}s")
      continue
    fi

    # Line 1: counts. Remaining lines: "severity|package|GHSA-id|cve|scope" per high/critical advisory.
    audit_out=$(printf '%s' "$audit_json" | node "$lib_dir/npm-audit.js" "$dir" 2>/dev/null)

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
    audit_progress composer "$dir"
    scanned_count=$((scanned_count + 1))

    if [ ! -f "$dir/composer.lock" ]; then
      skipped_lines+=("[composer] $dir: (composer.lock not found)")
      continue
    fi

    audit_json=$(run_limited "$audit_timeout" composer audit --format=json --locked --no-interaction -d "$dir")
    if [ $? -eq 124 ]; then
      error_lines+=("[composer] $dir: timed out after ${audit_timeout}s")
      continue
    fi

    # Line 1: counts. Remaining lines: "severity|package|id|cve|scope" per high/critical advisory.
    audit_out=$(printf '%s' "$audit_json" | node "$lib_dir/composer-audit.js" "$dir" 2>/dev/null)

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

[ -t 2 ] && printf '\r\033[2K' >&2

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
[ "$repo_attention" -gt 0 ] && echo "${c_yellow}⚠️  ${repo_attention} repo(s) need attention (branch / uncommitted changes / out of sync) — see the repo state section above.${c_reset}"

if [ $((total_critical + total_high)) -gt 0 ]; then
  echo
  echo "${c_bold}  High/Critical totals across ${#flagged_lines[@]} flagged package(s):${c_reset}"
  if [ "$total_critical" -gt 0 ]; then
    printf '  %s %s%-9s %6d%s  (in %d package(s))\n' "$(emoji_for_severity critical)" "$(color_for_severity critical)" "Critical" "$total_critical" "$c_reset" "$pkgs_critical"
  fi
  if [ "$total_high" -gt 0 ]; then
    printf '  %s %s%-9s %6d%s  (in %d package(s))\n' "$(emoji_for_severity high)" "$(color_for_severity high)" "High" "$total_high" "$c_reset" "$pkgs_high"
  fi
  printf '     %-9s %6d\n' "Combined" "$((total_critical + total_high))"
  [ "$use_epss" -eq 1 ] && echo "  ${c_dim}Counts are vulnerable packages per audit; the EPSS section below counts unique advisories.${c_reset}"
fi

if [ "$use_epss" -eq 1 ] && [ "${#epss_advisories[@]}" -gt 0 ]; then
  echo "Looking up EPSS scores for ${#epss_advisories[@]} advisory row(s)..." >&2
  # Output: "unique|scored|matched|failed|prodMatched|devMatched" header, then one
  # "epss%|severity|package|id|cve|scope|dir\x1fdir..." row per match (prod first, highest first).
  epss_out=$(printf '%s\n' "${epss_advisories[@]}" | node "$lib_dir/epss.js" "$epss_threshold" 2>/dev/null)

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
[ "${#error_lines[@]}" -gt 0 ] && exit 4
[ "$require_default" -eq 1 ] && [ "$repo_attention" -gt 0 ] && exit 3
exit 0
