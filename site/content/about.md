---
title: "About this feed"
description: "How the CraftedSignal Threat Feed works, what's in it, and how to subscribe."
---

## What this is

The CraftedSignal Threat Feed is a continuously refreshed catalog of trending threats, vulnerability exploitation, and threat-actor activity. Each brief includes:

- A short analysis of what the threat is and why it matters now
- MITRE ATT&CK tactic and technique mappings
- CVE references with EPSS, CVSS, and KEV status
- Affected vendors, products, and operating systems
- Detection-rule metadata (titles, MITRE coverage, data sources required)
- Counts of indicators of compromise by type

## What's not here

Detection rule queries (Sigma / SPL / KQL / FQL / LEQL), individual IOC values, full rule test data, and the complete brief body live inside the [CraftedSignal platform](https://app.craftedsignal.io/). The platform compiles each brief into ready-to-deploy SIEM rules with semantic-drift checks, noise budgets, and rollback automation.

## How to subscribe

Every page that lists briefs has its own RSS feed. The most useful entry points:

- [All briefs](/feed.xml) — everything
- [Critical only](/severities/critical/feed.xml)
- [High and above](/severities/high/feed.xml)
- Per [tag](/tags/) or [threat actor](/threat-actors/) — every term page links to its own feed

For email digests, paste any of these RSS URLs into a service like Buttondown, Feedrabbit, or Follow.it.

## How often it updates

Briefs are published continuously as new threat activity is observed. The site rebuilds on every commit to the underlying threat-feed repository.
