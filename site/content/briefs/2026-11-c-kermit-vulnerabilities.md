---
brief_id: brief-2026-11-02-c-kermit-vulnerabilities
event_id: brief-2026-11-02-c-kermit-vulnerabilities
revision: 2
activity_at: "2026-11-13T21:28:19Z"
revision_history:
  - revision: 2
    at: "2026-11-13T21:28:19Z"
    checksum: sha256:d302bb3e0ed7f89ee9f26d95ddc31c7753916774113777927be09e94cc9b3e84
    summary: poc_available; added CVE-2026-129125; c-kermit version < 11.1.515
    changed_fields:
      - action_plan
      - affected_products
      - claim_state
      - cpes
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-129125&utm_source=rss&utm_medium=rss
title: 'C-Kermit: Multiple vulnerabilities including RCE'
slug: 2026-11-c-kermit-vulnerabilities
description: Multiple vulnerabilities were discovered in the C-Kermit communication software during a code audit, including a remote code execution vector exploitable by a malicious peer and an authentication bypass with TLS certificate spoofing.
date: "2026-11-02T05:05:00Z"
lastmod: "2026-11-13T21:26:33Z"
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
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:openkermit:c_kermit:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-129125&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - rce
  - authentication-bypass
vendors:
  - OpenKermit
products:
  - C-Kermit
product_versions:
  - product: C-Kermit
    range: < 11.1.515
cves:
  - id: CVE-2026-129125
    cvss: 8.1
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/464
  - https://github.com/OpenKermit/ckermit/security/advisories/GHSA-c5px-7h4c-gj8p
  - https://sploitus.com/exploit?id=CVE-2026-129125&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch C-Kermit to 11.1.515 or later
      owner: IT Operations
      due: 48h
      evidence: Multiple vulnerabilities were discovered in the C-Kermit communication software during a code audit.
  hunt_leads:
    - lead: Monitor for C-Kermit process execution originating from network-facing activity or unexpected peer connection strings
      technique_id: T1059.003
      data_needed:
        - Process command line arguments
        - Network connection destination metadata
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The RCE is exploitable when working with a malicious peer.
  mitigation_plan:
    - priority: immediate
      action: Update C-Kermit to 11.1.515 or later
      owner: IT Operations
      addresses: RCE via malicious peer
      evidence: The findings include a remote code execution (RCE) vulnerability exploitable via interaction with a malicious peer.
updates:
  - at: "2026-11-13T21:26:33Z"
    level: L2
    summary: poc_available; added CVE-2026-129125; c-kermit version < 11.1.515
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-129125&utm_source=rss&utm_medium=rss
---

A code quality sweep of C-Kermit has identified three distinct security vulnerabilities. The most critical issue allows for remote code execution when a user interacts with a malicious peer. Additional vulnerabilities include an authentication bypass and TLS certificate spoofing. These issues are currently documented under GitHub Security Advisories; CVE identifiers are pending allocation. Users are advised to monitor the upstream repository for patch releases.

## Impact

Successful exploitation of the RCE vulnerability could allow an attacker to achieve remote code execution on the system running C-Kermit by simulating a malicious peer connection. The authentication bypass and TLS spoofing flaws compromise the integrity and confidentiality of communication sessions.

## Recommendation

* Monitor the C-Kermit GitHub repository and security advisories for the release of patched versions.
* Audit systems running C-Kermit to identify and restrict exposure to untrusted or public peer connections.
* Until patches are available, avoid connecting C-Kermit to untrusted remote peers, as these interactions facilitate the observed RCE and authentication bypass vectors.
