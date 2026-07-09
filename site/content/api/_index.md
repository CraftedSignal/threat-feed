---
title: "Feeds & API"
description: "Subscribe to the threat feed via RSS or JSON Feed. Every taxonomy term has its own filtered feed."
---

Every listing on this site doubles as a feed. Two formats are available: RSS 2.0 (`feed.xml`) and JSON Feed 1.0 (`feed.json`). Same items, same ordering. Use whichever your client supports.

## All briefs

- RSS: `https://feed.craftedsignal.io/feed.xml`
- JSON: `https://feed.craftedsignal.io/feed.json`

Items are ordered newest-first. Both feeds return up to 100 items. The JSON feed paginates beyond that. When another page exists, the response includes `next_url`.

## Filtered feeds

Replace `<term>` and `<slug>` with the value you want.

| Filter | RSS | JSON |
|---|---|---|
| Severity | `/severities/<term>/feed.xml` | `/severities/<term>/feed.json` |
| Type | `/types/<term>/feed.xml` | `/types/<term>/feed.json` |
| Product | `/products/<slug>/feed.xml` | `/products/<slug>/feed.json` |
| Vendor | `/vendors/<slug>/feed.xml` | `/vendors/<slug>/feed.json` |
| Actor | `/actors/<slug>/feed.xml` | `/actors/<slug>/feed.json` |
| Tag | `/tags/<slug>/feed.xml` | `/tags/<slug>/feed.json` |

Severity terms: critical, high, medium, low, rumour. Type terms: threat, coverage, advisory, rumour.

## STIX 2.1

Machine-readable [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro) bundles of the last 90 days of briefs, for TIP / SOAR ingestion. No auth, served from the static CDN.

- Latest 30 days: `https://feed.craftedsignal.io/stix.json`
- Per month: `https://feed.craftedsignal.io/stix/YYYY-MM.json` (e.g. `/stix/2026-05.json`)
- Manifest of available months: `https://feed.craftedsignal.io/stix/index.json`

Each bundle contains `report` objects linked to `indicator` (IOCs), `attack-pattern` (MITRE ATT&CK), `threat-actor`, `software` (affected vendor/product), and `vulnerability` (CVE) objects.

## JSON shape

```json
{
  "version": "1.0",
  "title": "CraftedSignal Threat Feed",
  "site_url": "https://feed.craftedsignal.io/",
  "feed_url": "https://feed.craftedsignal.io/feed.json",
  "items": [
    {
      "id": "/briefs/2026-04-some-cve/",
      "url": "https://feed.craftedsignal.io/briefs/2026-04-some-cve/",
      "title": "...",
      "summary": "...",
      "date": "2026-04-28T12:34:56Z",
      "type": "threat",
      "severities": ["critical"],
      "products": ["FortiGate"],
      "vendors": ["Fortinet"],
      "actors": [],
      "tags": ["cve"],
      "exploited": false,
      "cves": [{ "id": "CVE-2026-XXXX", "cvss": 9.8 }]
    }
  ]
}
```

## Tips

- **Slack** speaks RSS natively: `/feed subscribe https://feed.craftedsignal.io/severities/critical/feed.xml`.
- **Microsoft Teams** has an "RSS" connector. Point it at any of the URLs above.
- **Email aggregators** (Buttondown, Feedrabbit, Follow.it) will turn an RSS URL into per-item or daily-digest mail.
- **Custom integrations** can pull `feed.json` and decode it with your runtime's JSON library. No auth, no rate limit beyond the static-site CDN.

For per-subscriber filter combinations and channel routing (Slack/Teams webhooks, magic-link email confirmation), use the [subscribe form](/subscribe/) instead.

<a href="/" class="not-prose inline-flex mt-4 px-4 py-2 rounded-lg bg-accent text-white text-sm font-semibold">Back to feed</a>
