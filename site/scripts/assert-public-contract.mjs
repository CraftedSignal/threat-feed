import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const siteRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const publicRoot = resolve(
  process.env.SITE_OUTPUT || join(siteRoot, "public"),
);

function read(relativePath) {
  return readFileSync(join(publicRoot, relativePath), "utf8");
}

function matches(source, expression) {
  return [...source.matchAll(expression)].map((match) => match[1]);
}

function assertDocumentedPublicContract() {
  const api = read("api/index.html");
  for (const phrase of [
    "JSON Feed 1.1",
    "date_published",
    "_cs_type",
    "_cs_cves",
    "next_url",
    "2,000",
    "x_craftedsignal_brief_id",
    "x_craftedsignal_cvss_max",
    "report_count",
    "sha256:",
    "/stix/releases/",
  ]) {
    assert.match(api, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), `API documentation must include ${phrase}`);
  }
  assert.doesNotMatch(api, /JSON Feed 1\.0|Both feeds return up to 100 items/i);

  const about = read("about/index.html");
  const home = read("index.html");
  assert.match(about, />High only</);
  assert.doesNotMatch(`${about}\n${home}`, /High\+|High and above/);

  assert.match(
    home,
    /<link rel=(?:"alternate"|alternate) type=(?:"application\/rss\+xml"|application\/rss\+xml) href=(?:"https:\/\/feed\.craftedsignal\.io\/feed\.xml"|https:\/\/feed\.craftedsignal\.io\/feed\.xml)/,
  );
  assert.match(
    home,
    /<link rel=(?:"alternate"|alternate) type=(?:"application\/feed\+json"|application\/feed\+json) href=(?:"https:\/\/feed\.craftedsignal\.io\/feed\.json"|https:\/\/feed\.craftedsignal\.io\/feed\.json)/,
  );
  assert.doesNotMatch(home, /<link rel=(?:"alternate"|alternate)[^>]*href=(?:""|\s|>)/);

  const sitemap = read("sitemap.xml");
  const locations = matches(sitemap, /<loc>([^<]+)<\/loc>/g);
  assert.ok(locations.length > 0, "sitemap must contain canonical locations");
  assert.ok(locations.length <= 50_000, "sitemap must stay within the protocol limit");
  assert.equal(new Set(locations).size, locations.length, "sitemap locations must be unique");
  assert.ok(locations.every((location) => location.startsWith("https://feed.craftedsignal.io/")));

  assert.match(
    read("robots.txt"),
    /^Sitemap: https:\/\/feed\.craftedsignal\.io\/sitemap\.xml$/m,
  );
}

function assertInteractiveFilterContract() {
  const appSource = readFileSync(join(siteRoot, "assets/js/app.js"), "utf8");
  const commit = appSource.match(/function commit\(nextState\) \{([\s\S]*?)\n  \}/)?.[1] || "";
  assert.match(commit, /closeMenus\(\{ restoreFocus: true \}\)/, "committing a menu selection must return focus to its trigger");
  assert.doesNotMatch(appSource, /filterBriefs\(index\.items, state, index\.generated_at\)/, "Last 24 hours must not freeze at index build time");
}

function assertRSSRetention() {
  const fixtureRoot = mkdtempSync(join(tmpdir(), "threat-feed-rss-"));
  const contentDir = join(fixtureRoot, "content");
  const destination = join(fixtureRoot, "public");
  const briefsDir = join(contentDir, "briefs");
  mkdirSync(briefsDir, { recursive: true });
  writeFileSync(join(briefsDir, "_index.md"), "---\ntitle: Briefs\n---\n");
  for (let index = 0; index < 125; index += 1) {
    const day = String((index % 28) + 1).padStart(2, "0");
    writeFileSync(
      join(briefsDir, `fixture-${index}.md`),
      `---\ntitle: Fixture ${index}\nslug: fixture-${index}\ndate: 2026-09-${day}T12:00:00Z\ntype: advisory\nseverities: [high]\n---\nFixture.\n`,
    );
  }
  try {
    const result = spawnSync(
      "hugo",
      ["--quiet", "--contentDir", contentDir, "--destination", destination],
      { cwd: siteRoot, encoding: "utf8" },
    );
    assert.equal(result.status, 0, `Hugo RSS fixture build failed:\n${result.stderr}`);
    const itemCount = (readFileSync(join(destination, "feed.xml"), "utf8").match(/<item>/g) || []).length;
    assert.equal(itemCount, 125, "RSS must retain more than the JSON page size");
  } finally {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
}

assertDocumentedPublicContract();
assertInteractiveFilterContract();
assertRSSRetention();
console.log("public feed contract assertions passed");
