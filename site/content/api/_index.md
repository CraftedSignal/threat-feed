---
title: "Feeds & API"
description: "Subscribe to the threat feed via RSS or JSON Feed. Every taxonomy term has its own filtered feed."
---

Every listing on this site is also available as RSS 2.0 (`feed.xml`) and JSON Feed 1.1 (`feed.json`). Items use the same newest-first ordering in both formats.

## All briefs

- RSS: `https://feed.craftedsignal.io/feed.xml`
- JSON Feed: `https://feed.craftedsignal.io/feed.json`

RSS is a recent-items channel that retains up to 2,000 items. JSON Feed pages contain up to 100 items and are the completeness contract: follow the top-level `next_url` until it is absent.

## Filtered feeds

Replace `<term>` and `<slug>` with the value you want.

| Filter | RSS | JSON Feed |
|---|---|---|
| Severity | `/severities/<term>/feed.xml` | `/severities/<term>/feed.json` |
| Type | `/types/<term>/feed.xml` | `/types/<term>/feed.json` |
| Product | `/products/<slug>/feed.xml` | `/products/<slug>/feed.json` |
| Vendor | `/vendors/<slug>/feed.xml` | `/vendors/<slug>/feed.json` |
| Actor | `/actors/<slug>/feed.xml` | `/actors/<slug>/feed.json` |
| Tag | `/tags/<slug>/feed.xml` | `/tags/<slug>/feed.json` |

Severity terms are `critical`, `high`, `medium`, `low`, and `rumour`. Each endpoint is an exact match, so `/severities/high/feed.xml` contains **High only**. Type terms are `threat`, `coverage`, `advisory`, and `rumour`.

## JSON Feed 1.1 shape

The standard fields follow [JSON Feed 1.1](https://www.jsonfeed.org/version/1.1/). CraftedSignal metadata uses `_cs_*` extensions.

```json
{
  "version": "https://jsonfeed.org/version/1.1",
  "title": "CraftedSignal Threat Feed - CraftedSignal Threat Feed",
  "home_page_url": "https://feed.craftedsignal.io/",
  "feed_url": "https://feed.craftedsignal.io/feed.json",
  "next_url": "https://feed.craftedsignal.io/page/2/feed.json",
  "items": [
    {
      "id": "https://feed.craftedsignal.io/briefs/2026-04-some-cve/",
      "url": "https://feed.craftedsignal.io/briefs/2026-04-some-cve/",
      "title": "...",
      "summary": "...",
      "content_html": "<p>...</p>",
      "date_published": "2026-04-28T12:34:56Z",
      "date_modified": "2026-04-28T12:34:56Z",
      "_cs_type": "threat",
      "_cs_severities": ["critical"],
      "_cs_products": ["FortiGate"],
      "_cs_vendors": ["Fortinet"],
      "_cs_actors": [],
      "_cs_tags": ["cve"],
      "_cs_exploited": false,
      "_cs_has_poc": false,
      "_cs_poc_references": [],
      "_cs_cpes": [],
      "_cs_cves": [{ "id": "CVE-2026-XXXX", "cvss": 9.8 }]
    }
  ]
}
```

`next_url` appears only when another page exists. Treat unknown `_cs_*` fields as forward-compatible extensions.

## STIX 2.1

The static CDN publishes validated [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro) bundles for TIP and SOAR ingestion. No authentication is required.

- Rolling bundle: `https://feed.craftedsignal.io/stix.json`
- Monthly bundles: `https://feed.craftedsignal.io/stix/YYYY-MM.json`
- Bundle index: `https://feed.craftedsignal.io/stix/index.json`

A bundle uses the standard top-level `type`, `id`, and `objects` fields. Its reports reference the included `indicator`, `attack-pattern`, `threat-actor`, `software`, `vulnerability`, and identity objects with stable STIX IDs. Revisions retain their stable report ID, advance the report's `modified` timestamp, and expose the public revision number.

Every report includes these CraftedSignal properties:

- `x_craftedsignal_brief_id`, `x_craftedsignal_event_id`, and `x_craftedsignal_revision`
- `x_craftedsignal_canonical_url` for the canonical public brief
- `x_craftedsignal_activity_at`, `x_craftedsignal_severity`, and `x_craftedsignal_type`
- `x_craftedsignal_exploitation_evidence`
- `x_craftedsignal_cvss_max` and `x_craftedsignal_epss_max`, each a number or `null`
- `x_craftedsignal_kev_status`, one of `"true"`, `"false"`, or `"unknown"`

Each report also has a `craftedsignal` external reference whose `external_id` is the public brief ID and whose URL matches `x_craftedsignal_canonical_url`.

The index is version `2.0` and identifies both rolling and monthly scopes. Each entry records `path`, a `sha256:<64 lowercase hex>` checksum, `size_bytes`, `report_count`, `first_published`, `last_published`, `generated`, and STIX `spec_version`. Monthly entries also include `month`. Publication uploads bundles before the index so an index entry never points to a partially uploaded release.

## Tips

- **Slack** speaks RSS natively: `/feed subscribe https://feed.craftedsignal.io/severities/critical/feed.xml`.
- **Microsoft Teams** can consume any of the RSS URLs above through an RSS workflow or connector.
- **Email aggregators** can turn an RSS URL into per-item or daily-digest mail.
- **Custom integrations** should page through `feed.json` and ignore extension keys they do not recognize.

For per-subscriber filter combinations and channel routing, use the [subscribe form](/subscribe/).

<a href="/" class="not-prose inline-flex mt-4 px-4 py-2 rounded-lg bg-accent text-white text-sm font-semibold">Back to feed</a>
