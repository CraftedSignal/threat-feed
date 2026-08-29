---
title: Path Traversal Vulnerability in gpt-crawler via outputFileName Parameter
slug: 2026-08-gpt-crawler-traversal
description: CVE-2026-82286 is a path traversal vulnerability in gpt-crawler (<= 1.5.1) allowing unauthenticated attackers to perform arbitrary file writes through the /crawl endpoint.
date: "2026-08-28T21:39:26Z"
lastmod: "2026-08-29T02:36:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:builder:gpt-crawler:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=DC54923F-50AC-5F34-830F-42BEF1989C4E&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - cve
  - path-traversal
vendors:
  - Builder.io
products:
  - gpt-crawler (<= 1.5.1)
  - gpt-crawler
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The POST /crawl endpoint fails to properly validate the outputFileName parameter, allowing unauthenticated attackers to perform arbitrary file writes.
    confidence_band: high
cves:
  - id: CVE-2026-82286
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82286
  - https://sploitus.com/exploit?id=DC54923F-50AC-5F34-830F-42BEF1989C4E&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-82286 Exploitation - Path Traversal in gpt-crawler
    description: Detects attempts to exploit CVE-2026-82286 by monitoring POST requests to /crawl where the outputFileName parameter contains traversal patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch gpt-crawler to a version beyond 1.5.1
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-82286 affects versions through 1.5.1
  hunt_leads:
    - lead: Search logs for POST /crawl requests with path traversal characters in outputFileName
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source describes vulnerability in the POST /crawl endpoint
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the /crawl endpoint
      owner: IT Operations
      addresses: CVE-2026-82286
      evidence: Vulnerability allows unauthenticated access
updates:
  - at: "2026-08-29T02:36:27Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=DC54923F-50AC-5F34-830F-42BEF1989C4E&utm_source=rss&utm_medium=rss
---

CVE-2026-82286 is an arbitrary file write vulnerability affecting gpt-crawler versions up to and including 1.5.1. The flaw exists within the POST /crawl endpoint, which fails to adequately sanitize the 'outputFileName' parameter. An unauthenticated attacker can exploit this lack of validation by supplying crafted input containing path traversal sequences (e.g., ../) or absolute filesystem paths. 

By manipulating this parameter, an attacker can influence where the crawler writes its output, enabling the overwriting of critical system files or configuration files with content fetched from attacker-controlled URLs. If successfully exploited, this can lead to remote code execution or system compromise depending on the overwritten target. Defenders should prioritize patching gpt-crawler to a fixed version or restricting access to the /crawl endpoint to authorized users only.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to achieve arbitrary file writes on the host system. This can lead to system-level configuration changes, the overwriting of binaries, or the placement of malicious web shells. The scope of impact includes any environment where gpt-crawler is deployed with external-facing access.

## Recommendation

- Upgrade gpt-crawler to a version beyond 1.5.1 immediately.
- Implement access control mechanisms to prevent unauthenticated access to the /crawl API endpoint.
- Audit existing deployments for logs showing unexpected POST requests to /crawl where the 'outputFileName' parameter contains directory traversal characters.
