"use strict";

// Reads `composer audit --format=json` from stdin; argv[2] is the package directory holding composer.lock.
// Output line 1: "info|low|moderate|high|critical|total".
// Then one "severity|package|id|cve|scope" row per high/critical advisory (id prefers the GHSA id).
// scope is "dev" only when the package appears in packages-dev and not in packages.

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
    const lock = JSON.parse(fs.readFileSync(path.join(process.argv[2], "composer.lock"), "utf8"));
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
