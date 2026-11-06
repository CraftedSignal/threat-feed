---
brief_id: brief-2026-11-06-charmbracelet-wish-path-traversal
event_id: brief-2026-11-06-charmbracelet-wish-path-traversal
revision: 2
activity_at: "2026-11-06T17:37:45Z"
revision_history:
  - revision: 2
    at: "2026-11-06T17:37:45Z"
    checksum: sha256:ec0bde4341df2ae3486f0f35aaf70a5e8a21226528db901427cedda7a4a8455b
    summary: new product
    changed_fields:
      - affected_products
      - affected_vendors
      - claim_state
      - cpes
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/charmbracelet-wish-git-middleware-path-traversal-cve-2026-53980
title: 'Charmbracelet wish: Path traversal vulnerability (CVE-2026-53980)'
slug: 2026-11-charmbracelet-wish-path-traversal
description: Charmbracelet wish contains a path traversal vulnerability in the git middleware that allows authenticated SSH users to access arbitrary repositories outside the intended root directory.
date: "2026-11-06T17:26:24Z"
lastmod: "2026-11-06T17:36:45Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:charmbracelet:wish:*:*:*:*:*:*:*:*
vendors:
  - Charmbracelet
products:
  - Wish (< 2.0.5)
cves:
  - id: CVE-2026-53980
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53980
  - https://pwn.watch/i/charmbracelet-wish-git-middleware-path-traversal-cve-2026-53980
  - https://github.com/charmbracelet/wish/releases/tag/v2.0.5
  - https://github.com/charmbracelet/wish/commit/533db0daa90446b0d4ae3284877179c37e0cc48e
updates:
  - at: "2026-11-06T17:36:45Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/charmbracelet-wish-git-middleware-path-traversal-cve-2026-53980
---

Charmbracelet wish contains a path traversal vulnerability in its git middleware (charm.land/wish/v2). The flaw stems from a flawed forward-slash-count containment check in git.Middleware(). Authenticated SSH users can supply crafted repository paths - such as single-depth paths like '../evil' or, on Windows, payloads like '..\..\evil' - to bypass the guard. This allows users to read or write arbitrary repositories outside the intended root directory via git-upload-pack, git-upload-archive, or git-receive-pack.
