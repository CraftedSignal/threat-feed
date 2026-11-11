---
brief_id: brief-2026-11-11-react-rce
event_id: brief-2026-11-11-react-rce
revision: 1
activity_at: "2026-11-11T07:26:10Z"
title: 'React: Unauthenticated Remote Code Execution in React Server Components (CVE-2026-126187)'
slug: 2026-11-react-rce
description: A critical remote code execution vulnerability in React Server Components packages allows unauthenticated attackers to execute code via crafted responses involving multiple typed arrays.
date: "2026-11-11T07:26:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
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
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-xqc2-xf4c-x3h3
---

CVE-2026-126187 is a critical remote code execution vulnerability affecting react-server-dom-webpack, react-server-dom-parcel, and react-server-dom-turbopack. The vulnerability occurs in rare cases where responses transport multiple typed arrays and an attacker-controlled value.

## Scope
This affects applications using frameworks that support React Server Components. Applications not using a server, or not using a framework, bundler, or bundler plugin that supports React Server Components, are not affected.

## Recommendation
Upgrade affected packages to versions 19.0.9, 19.1.10, 19.2.9, or 19.3.1.
