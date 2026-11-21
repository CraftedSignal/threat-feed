---
brief_id: brief-2026-11-20-refitter-rce-ghsa-3fhm-p725-h3g3
event_id: brief-2026-11-20-refitter-rce-ghsa-3fhm-p725-h3g3
revision: 2
activity_at: "2026-11-21T09:48:35Z"
revision_history:
  - revision: 2
    at: "2026-11-21T09:48:35Z"
    checksum: sha256:b5e143bfbcae908aefaeebadc70a9b512e489c6f2739b2fb40f28f5ff0e0c8d8
    summary: poc_available
    changed_fields:
      - cve_verification
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=A5E589C2-59A3-5577-A2F4-42884C32A01D&utm_source=rss&utm_medium=rss
title: 'Refitter: Arbitrary Code Execution via Unescaped OpenAPI Paths (CVE-2026-63345)'
slug: 2026-11-refitter-rce-ghsa-3fhm-p725-h3g3
description: Refitter versions prior to 2.1.2 fail to escape OpenAPI path keys when generating C# Refit attributes, allowing an attacker-influenced OpenAPI specification to inject arbitrary code that executes upon assembly loading via a ModuleInitializer.
date: "2026-11-20T02:03:06Z"
lastmod: "2026-11-21T09:47:36Z"
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
cpes:
  - cpe:2.3:a:christianhelle:refitter:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=A5E589C2-59A3-5577-A2F4-42884C32A01D&utm_source=rss&utm_medium=rss
tags:
  - cwe-74
  - cwe-77
vendors:
  - christianhelle
products:
  - refitter
cve_verification:
  CVE-2026-63345:
    status: verified
    source: nvd
    checked_at: 2026-11-21T09:47:16.991620317Z
cves:
  - id: CVE-2026-63345
    epss: 0.0035
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-3fhm-p725-h3g3
  - https://cveawg.mitre.org/api/cve/CVE-2026-63345
  - https://sploitus.com/exploit?id=A5E589C2-59A3-5577-A2F4-42884C32A01D&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-21T09:47:36Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=A5E589C2-59A3-5577-A2F4-42884C32A01D&utm_source=rss&utm_medium=rss
---

## Overview
Refitter is a tool for generating C# REST API clients using the Refit library. In versions prior to 2.1.2, the tool emits OpenAPI `paths`-object keys verbatim into Refit route attributes (e.g., `[Get("<path>")]`) without escaping quotation marks or restricting characters. An attacker can provide a single-line, slash-prefixed path that escapes the attribute string, closes the interface and namespace, and injects a top-level `file class` with a `[ModuleInitializer]` method. This behavior survives default OpenAPI validation. The vulnerability was verified on Refitter 2.0.0 using .NET 8.

## Impact
When an application compiles and loads a Refitter-generated assembly, the injected `[ModuleInitializer]` method executes, resulting in arbitrary code execution at process startup. This occurs even if the generated client is not explicitly called. Additionally, the raw emission of header parameter names within `[Header("<name>")]` attributes can lead to build-breaking Denial of Service.

## Recommendation
The vulnerability is fixed in Refitter version 2.1.2. Users should upgrade to this version to ensure proper escaping of route templates and header attributes.
