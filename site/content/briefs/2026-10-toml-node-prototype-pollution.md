---
brief_id: brief-2026-10-23-toml-node-prototype-pollution
event_id: brief-2026-10-23-toml-node-prototype-pollution
revision: 1
activity_at: "2026-10-23T06:44:24Z"
title: 'toml: Prototype pollution via ambiguous TOML key paths (CVE-2026-114142)'
slug: 2026-10-toml-node-prototype-pollution
description: The toml package is vulnerable to prototype pollution, allowing unauthorized injection of properties into Object.prototype via maliciously crafted TOML documents.
date: "2026-10-23T06:44:24Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
tags:
  - prototype-pollution
  - nodejs
products:
  - toml (<= 5.0.0)
cves:
  - id: CVE-2026-114142
    epss: 0.00315
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-h895-cgqg-jf52
---

The toml package (up to and including version 5.0.0) is susceptible to prototype pollution. The vulnerability arises from ambiguous key-path encoding where `quoteDottedString()` fails to escape double quotes, leading to path desynchronization. Combined with a table-array header that can clear security guards and a lack of `isOwnedContainer` checks during the `assign()` descent, an attacker can traverse into an object's prototype chain. Successfully crafting a specific TOML document allows for the injection of arbitrary properties into `Object.prototype`, which then become visible to every object in the Node.js process.
