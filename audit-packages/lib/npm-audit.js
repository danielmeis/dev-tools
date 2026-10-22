"use strict";

// Reads `npm audit --json` from stdin; argv[2] is the package directory holding package-lock.json.
// Output line 1: "info|low|moderate|high|critical|total".
// Then one "severity|package|id|cve|scope" row per unique high/critical advisory (cve is always empty here).
// scope is "dev" only when the lockfile marks every installed copy of the package as dev-only.

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
    lockPkgs = JSON.parse(fs.readFileSync(path.join(process.argv[2], "package-lock.json"), "utf8")).packages || {};
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
