#!/usr/bin/env node
// VibeReview on-the-fly SCA — queries the public OSV.dev API for known
// vulnerabilities in the exact packages/versions an agent is about to add to a
// project. On a HIGH/CRITICAL finding it recommends the nearest safe (fixed)
// version so the agent can auto-substitute it and keep building, rather than
// blocking the developer's flow. The avoided vuln is meant to be flagged in
// the response and recorded in VibeReview telemetry (threats mitigated).
//
// Zero runtime dependencies: uses the global `fetch` shipped with Node >= 18.
// No API key is required — https://api.osv.dev is a free, unauthenticated,
// read-only vulnerability database (OpenSSF / Google OSV).
//
// Usage:
//   node osv-scan.mjs --ecosystem npm lodash@4.17.15 axios@0.21.0
//   node osv-scan.mjs --ecosystem PyPI requests@2.19.0
//   node osv-scan.mjs --ecosystem npm --json next@13.4.0
//   echo '[{"ecosystem":"npm","name":"lodash","version":"4.17.15"}]' | node osv-scan.mjs --stdin
//
// Exit codes:
//   0  no packages at or above the severity threshold (default: HIGH)
//   1  at least one package has a vuln at/above the threshold (REMEDIATE)
//   2  a package could not be evaluated (unknown severity / network error)
//   3  bad usage
//
// Exit code 1 means "remediate, don't block": substitute the recommended safe
// version (printed as "→ use name@version" / the `recommended` JSON field),
// re-scan it, and continue. Exit code 2 means proceed but flag residual risk.
// The point is to keep the vulnerable version out of the codebase without
// interrupting the developer.

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";

// Map of human-friendly ecosystem aliases -> the canonical OSV ecosystem name.
// OSV is case-sensitive, so normalising here avoids silent empty results.
const ECOSYSTEM_ALIASES = new Map([
  ["npm", "npm"],
  ["node", "npm"],
  ["yarn", "npm"],
  ["pnpm", "npm"],
  ["pypi", "PyPI"],
  ["pip", "PyPI"],
  ["python", "PyPI"],
  ["poetry", "PyPI"],
  ["go", "Go"],
  ["golang", "Go"],
  ["maven", "Maven"],
  ["gradle", "Maven"],
  ["java", "Maven"],
  ["rubygems", "RubyGems"],
  ["gem", "RubyGems"],
  ["ruby", "RubyGems"],
  ["cargo", "crates.io"],
  ["crates", "crates.io"],
  ["crates.io", "crates.io"],
  ["rust", "crates.io"],
  ["nuget", "NuGet"],
  ["dotnet", "NuGet"],
  ["composer", "Packagist"],
  ["packagist", "Packagist"],
  ["php", "Packagist"],
  ["hex", "Hex"],
  ["elixir", "Hex"],
  ["pub", "Pub"],
  ["dart", "Pub"],
]);

const SEVERITY_ORDER = { UNKNOWN: -1, LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

function bucketFromScore(score) {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0) return "LOW";
  return "UNKNOWN";
}

function bucketFromLabel(label) {
  if (!label) return "UNKNOWN";
  const upper = String(label).toUpperCase();
  if (upper === "CRITICAL") return "CRITICAL";
  if (upper === "HIGH") return "HIGH";
  if (upper === "MODERATE" || upper === "MEDIUM") return "MEDIUM";
  if (upper === "LOW") return "LOW";
  return "UNKNOWN";
}

function maxBucket(a, b) {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

// Official CVSS v3.1 roundup: round up to the nearest 0.1.
function cvssRoundUp(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

// Compute a CVSS v3.x base score from a vector string. Returns null for
// vectors we cannot parse (e.g. CVSS v4, which uses a different model).
function cvss3BaseScore(vector) {
  const parts = {};
  for (const segment of vector.split("/")) {
    const [k, v] = segment.split(":");
    if (k && v) parts[k] = v;
  }
  if (!parts.AV || !parts.AC || !parts.PR || !parts.UI || !parts.S || !parts.C || !parts.I || !parts.A) {
    return null;
  }
  const scopeChanged = parts.S === "C";
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[parts.AV];
  const AC = { L: 0.77, H: 0.44 }[parts.AC];
  const PR = scopeChanged
    ? { N: 0.85, L: 0.68, H: 0.5 }[parts.PR]
    : { N: 0.85, L: 0.62, H: 0.27 }[parts.PR];
  const UI = { N: 0.85, R: 0.62 }[parts.UI];
  const cia = { N: 0, L: 0.22, H: 0.56 };
  const C = cia[parts.C];
  const I = cia[parts.I];
  const A = cia[parts.A];
  if ([AV, AC, PR, UI, C, I, A].some((x) => x === undefined)) return null;

  const iss = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const exploitability = 8.22 * AV * AC * PR * UI;
  if (impact <= 0) return 0;
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return cvssRoundUp(raw);
}

// Best numeric score we can derive from an OSV `severity[]` array.
function scoreFromSeverityArray(severityArr) {
  let best = null;
  for (const entry of severityArr ?? []) {
    const type = entry?.type ?? "";
    const score = entry?.score ?? "";
    if (typeof score === "string" && score.startsWith("CVSS:3")) {
      const computed = cvss3BaseScore(score);
      if (computed != null) best = best == null ? computed : Math.max(best, computed);
    } else if (typeof score === "string" && /^\d+(\.\d+)?$/.test(score)) {
      const n = Number(score);
      best = best == null ? n : Math.max(best, n);
    }
  }
  return best;
}

// Decide a single severity bucket for one OSV vuln record, combining the CVSS
// vector (authoritative when present) with the GHSA-style text label.
function severityForVuln(vuln) {
  let bucket = "UNKNOWN";
  const score = scoreFromSeverityArray(vuln.severity);
  if (score != null) bucket = maxBucket(bucket, bucketFromScore(score));

  const labels = [vuln?.database_specific?.severity];
  for (const aff of vuln.affected ?? []) {
    labels.push(aff?.database_specific?.severity);
  }
  for (const label of labels) {
    bucket = maxBucket(bucket, bucketFromLabel(label));
  }
  return { bucket, score };
}

// Pull the fixed-version events out of an OSV vuln so the agent can recommend a
// safe upgrade target instead of just rejecting the package.
function fixedVersions(vuln) {
  const fixes = new Set();
  for (const aff of vuln.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) fixes.add(event.fixed);
      }
    }
  }
  return [...fixes];
}

// Best-effort, ecosystem-agnostic version comparison. Strips a leading "v",
// compares dot-separated segments numerically where possible. Good enough to
// pick the highest published "fixed" version as the recommended safe target;
// the agent still confirms compatibility and re-scans.
function compareVersions(a, b) {
  const norm = (v) => String(v).replace(/^v/i, "").split(/[.+-]/);
  const pa = norm(a);
  const pb = norm(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const sa = pa[i] ?? "0";
    const sb = pb[i] ?? "0";
    const na = Number(sa);
    const nb = Number(sb);
    const bothNumeric = !Number.isNaN(na) && !Number.isNaN(nb);
    if (bothNumeric) {
      if (na !== nb) return na - nb;
    } else if (sa !== sb) {
      return sa < sb ? -1 : 1;
    }
  }
  return 0;
}

// The recommended safe version: the highest published `fixed` version across
// the findings we want to escape (fixes are normally cumulative, so the
// highest fix clears the earlier ones too). Returns null if no fix exists.
function recommendedVersion(findings) {
  let best = null;
  for (const f of findings) {
    for (const fixed of f.fixed ?? []) {
      if (best == null || compareVersions(fixed, best) > 0) best = fixed;
    }
  }
  return best;
}

function advisoryUrl(vuln) {
  const ghsa = (vuln.aliases ?? []).find((a) => a.startsWith("GHSA-")) ?? vuln.id;
  if (vuln.id?.startsWith("GHSA-")) return `https://github.com/advisories/${vuln.id}`;
  if (ghsa?.startsWith("GHSA-")) return `https://github.com/advisories/${ghsa}`;
  return `https://osv.dev/vulnerability/${vuln.id}`;
}

async function queryOsv(pkg) {
  const body = {
    package: { name: pkg.name, ecosystem: pkg.ecosystem },
  };
  if (pkg.version) body.version = pkg.version;
  const res = await fetch(OSV_QUERY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`OSV API ${res.status} for ${pkg.ecosystem}:${pkg.name}@${pkg.version ?? "*"}`);
  }
  const data = await res.json();
  return data.vulns ?? [];
}

function parsePackageArg(arg, ecosystem) {
  // Accept "name@version", scoped "@scope/name@version", or bare "name".
  const at = arg.lastIndexOf("@");
  if (at > 0) {
    return { ecosystem, name: arg.slice(0, at), version: arg.slice(at + 1) };
  }
  return { ecosystem, name: arg, version: undefined };
}

function thresholdRank(threshold) {
  return SEVERITY_ORDER[threshold] ?? SEVERITY_ORDER.HIGH;
}

async function main() {
  const argv = process.argv.slice(2);
  let ecosystem = null;
  let json = false;
  let stdin = false;
  let threshold = "HIGH";
  const positional = [];

  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--ecosystem" || a === "-e") {
      ecosystem = argv[++i];
    } else if (a === "--json") {
      json = true;
    } else if (a === "--stdin") {
      stdin = true;
    } else if (a === "--severity-threshold" || a === "-t") {
      threshold = String(argv[++i] ?? "HIGH").toUpperCase();
    } else if (a === "--help" || a === "-h") {
      printHelp();
      process.exit(0);
    } else {
      positional.push(a);
    }
  }

  if (!(threshold in SEVERITY_ORDER) || threshold === "UNKNOWN") {
    process.stderr.write(`Invalid --severity-threshold "${threshold}". Use LOW|MEDIUM|HIGH|CRITICAL.\n`);
    process.exit(3);
  }

  let packages = [];
  if (stdin) {
    const raw = await readStdin();
    try {
      const parsed = JSON.parse(raw);
      packages = (Array.isArray(parsed) ? parsed : [parsed]).map((p) => ({
        ecosystem: normalizeEcosystem(p.ecosystem ?? ecosystem),
        name: p.name,
        version: p.version,
      }));
    } catch {
      process.stderr.write("--stdin expected a JSON array of {ecosystem,name,version}.\n");
      process.exit(3);
    }
  } else {
    if (!ecosystem) {
      process.stderr.write("Missing --ecosystem (e.g. npm, PyPI, Go, Maven, crates.io, NuGet, RubyGems, Packagist).\n");
      process.exit(3);
    }
    const canonical = normalizeEcosystem(ecosystem);
    packages = positional.map((arg) => parsePackageArg(arg, canonical));
  }

  if (packages.length === 0) {
    printHelp();
    process.exit(3);
  }

  const results = [];
  let blocked = 0;
  let unevaluated = 0;

  for (const pkg of packages) {
    if (!pkg.name || !pkg.ecosystem) {
      results.push({ package: pkg, status: "error", error: "missing name or ecosystem" });
      unevaluated += 1;
      continue;
    }
    try {
      const vulns = await queryOsv(pkg);
      const findings = vulns
        .map((v) => {
          const { bucket, score } = severityForVuln(v);
          return {
            id: v.id,
            aliases: v.aliases ?? [],
            severity: bucket,
            cvss: score,
            summary: v.summary ?? v.details?.slice(0, 160) ?? "",
            fixed: fixedVersions(v),
            url: advisoryUrl(v),
            withdrawn: Boolean(v.withdrawn),
          };
        })
        .filter((f) => !f.withdrawn);

      const atOrAboveThreshold = findings.filter(
        (f) => SEVERITY_ORDER[f.severity] >= thresholdRank(threshold),
      );
      const unknowns = findings.filter((f) => f.severity === "UNKNOWN");
      const status = atOrAboveThreshold.length > 0 ? "remediate" : unknowns.length > 0 ? "review" : "ok";
      const recommended = status === "remediate" ? recommendedVersion(atOrAboveThreshold) : null;
      if (status === "remediate") blocked += 1;
      if (status === "review") unevaluated += 1;
      results.push({ package: pkg, status, recommended, findings });
    } catch (err) {
      results.push({ package: pkg, status: "error", error: err.message });
      unevaluated += 1;
    }
  }

  if (json) {
    process.stdout.write(
      `${JSON.stringify({ threshold, blocked, unevaluated, results }, null, 2)}\n`,
    );
  } else {
    printHuman(results, threshold);
  }

  if (blocked > 0) process.exit(1);
  if (unevaluated > 0) process.exit(2);
  process.exit(0);
}

function normalizeEcosystem(value) {
  if (!value) return value;
  const alias = ECOSYSTEM_ALIASES.get(String(value).trim().toLowerCase());
  return alias ?? value;
}

function printHuman(results, threshold) {
  const out = [];
  out.push(`OSV.dev SCA — severity threshold: ${threshold} (auto-remediate at or above)`);
  out.push("");
  for (const r of results) {
    const { ecosystem, name, version } = r.package;
    const id = `${ecosystem}:${name}@${version ?? "*"}`;
    if (r.status === "ok") {
      out.push(`  [OK]        ${id} — no known vulnerabilities at/above ${threshold}`);
    } else if (r.status === "error") {
      out.push(`  [RISK]      ${id} — ${r.error} (proceed but flag as residual risk)`);
    } else {
      const tag = r.status === "remediate" ? "FIX" : "RISK";
      const hint = r.status === "remediate"
        ? r.recommended
          ? `→ use ${name}@${r.recommended}`
          : "→ no published fix; prefer a safe alternative or flag residual risk"
        : "→ unknown severity; proceed but flag as residual risk";
      out.push(`  [${tag}]${tag === "FIX" ? "       " : "      "}${id}  ${hint}`);
      const ranked = [...r.findings].sort(
        (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
      );
      for (const f of ranked) {
        const fixed = f.fixed.length ? `fixed: ${f.fixed.join(", ")}` : "fixed: (none published)";
        const cvss = f.cvss != null ? ` CVSS ${f.cvss}` : "";
        out.push(`            - ${f.severity}${cvss} ${f.id} — ${truncate(f.summary, 100)}`);
        out.push(`              ${fixed} | ${f.url}`);
      }
    }
  }
  out.push("");
  const remediate = results.filter((r) => r.status === "remediate");
  const review = results.filter((r) => r.status === "review" || r.status === "error").length;
  if (remediate.length > 0) {
    const fixes = remediate
      .map((r) => `${r.package.name}@${r.package.version ?? "*"}${r.recommended ? ` → ${r.recommended}` : " → (no fix; use alternative)"}`)
      .join("; ");
    out.push(`RESULT: REMEDIATE — ${remediate.length} package(s) carry ${threshold}+ vulnerabilities. Do not interrupt the user: substitute the safe version and keep building (${fixes}). Re-scan the chosen version, and record the avoided vuln in VibeReview telemetry.`);
  } else if (review > 0) {
    out.push(`RESULT: RESIDUAL RISK — ${review} package(s) could not be evaluated (unknown severity / OSV unreachable). Proceed but flag them as residual risk in the summary and telemetry.`);
  } else {
    out.push("RESULT: PASS — all scanned packages are clear at/above the threshold.");
  }
  process.stdout.write(`${out.join("\n")}\n`);
}

function truncate(text, n) {
  if (!text) return "";
  const clean = String(text).replace(/\s+/g, " ").trim();
  return clean.length > n ? `${clean.slice(0, n - 1)}…` : clean;
}

function readStdin() {
  return new Promise((resolveFn) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolveFn(data));
  });
}

function printHelp() {
  process.stdout.write(
    [
      "VibeReview OSV.dev SCA scanner",
      "",
      "Usage:",
      "  node osv-scan.mjs --ecosystem <eco> <name@version> [<name@version> ...]",
      "  node osv-scan.mjs --stdin   # reads JSON array of {ecosystem,name,version}",
      "",
      "Options:",
      "  -e, --ecosystem <eco>          npm | PyPI | Go | Maven | crates.io | NuGet | RubyGems | Packagist | Hex | Pub",
      "  -t, --severity-threshold <s>   LOW | MEDIUM | HIGH | CRITICAL  (default: HIGH)",
      "      --json                     machine-readable output",
      "      --stdin                    read packages as JSON on stdin",
      "",
      "Exit: 0 clean · 1 remediate (>=threshold; use recommended safe version) · 2 residual risk/error · 3 bad usage",
    ].join("\n") + "\n",
  );
}

main().catch((err) => {
  process.stderr.write(`osv-scan fatal: ${err?.message ?? err}\n`);
  process.exit(2);
});
