---
brief_id: brief-2026-11-11-react-rce
event_id: brief-2026-11-11-react-rce
revision: 2
activity_at: "2026-11-12T01:01:34Z"
revision_history:
  - revision: 2
    at: "2026-11-12T01:01:34Z"
    checksum: sha256:6c88a50babd494a649446b13a74455ad81e9609e732ceeabe08df83a400d35c6
    summary: exploited:true; poc_available
    changed_fields:
      - claim_state
      - exploitation_evidence
      - has_poc
      - lastmod
      - poc_references
      - priority_score
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=198D0076-AF12-50FD-977F-A72535264ADC&utm_source=rss&utm_medium=rss
title: 'React: Unauthenticated Remote Code Execution in React Server Components (CVE-2026-126187)'
slug: 2026-11-react-rce
description: A critical remote code execution vulnerability in React Server Components packages allows unauthenticated attackers to execute code via crafted responses involving multiple typed arrays.
date: "2026-11-11T07:26:10Z"
lastmod: "2026-11-12T01:00:35Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://sploitus.com/exploit?id=198D0076-AF12-50FD-977F-A72535264ADC&utm_source=rss&utm_medium=rss
  observed_at: "2026-11-11T20:40:34Z"
  confidence: medium
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=198D0076-AF12-50FD-977F-A72535264ADC&utm_source=rss&utm_medium=rss
tags:
  - remote-code-execution
  - react
  - cve-2026-126187
products:
  - react-server-dom-webpack
  - react-server-dom-parcel
  - react-server-dom-turbopack
cves:
  - id: CVE-2026-126187
    epss: 0.01763
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-xqc2-xf4c-x3h3
  - https://sploitus.com/exploit?id=198D0076-AF12-50FD-977F-A72535264ADC&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-12T01:00:35Z"
    level: L3
    summary: exploited:true; poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=198D0076-AF12-50FD-977F-A72535264ADC&utm_source=rss&utm_medium=rss
---

CVE-2026-126187 is a critical remote code execution vulnerability affecting react-server-dom-webpack, react-server-dom-parcel, and react-server-dom-turbopack. The vulnerability occurs in rare cases where responses transport multiple typed arrays and an attacker-controlled value.

## Scope
This affects applications using frameworks that support React Server Components. Applications not using a server, or not using a framework, bundler, or bundler plugin that supports React Server Components, are not affected.

## Recommendation
Upgrade affected packages to versions 19.0.9, 19.1.10, 19.2.9, or 19.3.1.
