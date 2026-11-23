---
brief_id: brief-2026-08-fortinet-fortisiem-data-manipulation
event_id: brief-2026-08-fortinet-fortisiem-data-manipulation
revision: 2
activity_at: "2026-11-23T10:28:26Z"
revision_history:
  - revision: 2
    at: "2026-11-23T10:28:26Z"
    checksum: sha256:eaba9db5bd1a474d6727f1fccf38d5765ac6cf6ff786920fd9245863bd0d8a5b
    summary: poc_available
    changed_fields:
      - cve_verification
      - cves
      - has_poc
      - lastmod
      - poc_references
      - priority_signals
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORIZON3AI-CVE-2024-23108&utm_source=rss&utm_medium=rss
title: Data Manipulation Vulnerability in Fortinet FortiSIEM
slug: 2026-08-fortinet-fortisiem-data-manipulation
description: A vulnerability in Fortinet FortiSIEM allows a remote, authenticated attacker to manipulate system data, posing a risk to data integrity within the security platform.
date: "2026-08-13T12:42:20Z"
lastmod: "2026-11-23T10:28:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: validated against source material
cpes:
  - cpe:2.3:a:fortinet:fortisiem:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortisiem:7.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortisiem:7.1.1:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORIZON3AI-CVE-2024-23108&utm_source=rss&utm_medium=rss
vendors:
  - Fortinet
products:
  - FortiSIEM
cve_verification:
  CVE-2024-23108:
    status: verified
    source: nvd
    checked_at: 2026-11-23T10:28:10.400662328Z
cves:
  - id: CVE-2024-23108
    cvss: 10
    epss: 0.80304
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2813
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORIZON3AI-CVE-2024-23108&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch FortiSIEM instances according to Fortinet security advisories for CVE-2024-23108
      owner: IT Operations
      due: 72h
      evidence: Advisory requires remediation via system update
  mitigation_plan:
    - priority: immediate
      action: Audit and rotate credentials for all accounts with administrative or data-write privileges in FortiSIEM
      owner: IT Operations
      addresses: CVE-2024-23108
      evidence: Vulnerability requires authentication to exploit
updates:
  - at: "2026-11-23T10:28:10Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORIZON3AI-CVE-2024-23108&utm_source=rss&utm_medium=rss
---

## Overview

The German Federal Office for Information Security (BSI) has released a security advisory regarding a vulnerability in Fortinet FortiSIEM. This flaw allows a remote, authenticated attacker to perform unauthorized data manipulation within the FortiSIEM environment. By leveraging the identified vulnerability, documented as CVE-2024-23108, an attacker who has already achieved authentication to the system can compromise the integrity of security logs, configuration data, or other sensitive information handled by the SIEM. Because this flaw requires an existing authentication context, defenders should prioritize the review of access controls and monitor for suspicious administrative or data-altering actions performed by authenticated service accounts or user sessions.

## Impact

The successful exploitation of this vulnerability results in the degradation of data integrity within FortiSIEM. This could allow an attacker to obfuscate malicious activity by altering security logs, bypassing detection rules, or modifying operational settings. Organizations relying on FortiSIEM for centralized visibility and incident response are particularly at risk, as the integrity of the SIEM platform is foundational to effective security operations.

## Recommendation

Prioritize the identification and application of firmware updates provided by Fortinet for affected FortiSIEM installations. Since the attack requires authentication, monitor for anomalous activity in administrative sessions, such as unexpected API calls or file modification events, for all users who have access to the SIEM's backend or data management functions.
