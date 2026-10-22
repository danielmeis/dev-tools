"use strict";

// Reads "severity|package|id|cve|scope|dir" rows from stdin; argv[2] is the minimum EPSS probability (0-1).
// Resolves missing CVEs from GHSA ids via OSV.dev, then fetches EPSS scores from FIRST.org.
// Output line 1: "unique|scored|matched|failed|prodMatched|devMatched".
// Then one "epss%|severity|package|id|cve|scope|dir\x1fdir..." row per match: prod before dev-only, highest score first.

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;
const threshold = parseFloat(process.argv[2]);

const getJson = async (url) => {
  const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
  if (!res.ok) throw new Error(String(res.status));
  return res.json();
};

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
  // CVE ids end up in a URL and on the terminal, so anything malformed is dropped.
  for (const it of items) {
    if (it.cve && !CVE_PATTERN.test(it.cve)) it.cve = "";
  }

  const needCve = items.filter((i) => !i.cve && /^GHSA-/.test(i.id));
  for (let i = 0; i < needCve.length; i += 10) {
    await Promise.all(needCve.slice(i, i + 10).map(async (it) => {
      try {
        const v = await getJson("https://api.osv.dev/v1/vulns/" + encodeURIComponent(it.id));
        const alias = (v.aliases || []).find((a) => CVE_PATTERN.test(a));
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
