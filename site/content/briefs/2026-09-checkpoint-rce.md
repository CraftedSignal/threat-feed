---
title: Remote Code Execution Vulnerability in Check Point Management Products
slug: 2026-09-checkpoint-rce
description: A critical remote code execution vulnerability (CVE-2026-91843) affects multiple Check Point security management servers, allowing unauthenticated attackers to execute arbitrary code.
date: "2026-09-17T13:08:53Z"
lastmod: "2026-09-18T04:24:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - network-security
vendors:
  - Check Point
products:
  - Log Server (< R81.20 take 28, < R82 take 28, < R82.10 take 28, < R82.20 take 29)
  - Multi-Domain Log Server (< R81.20 take 28, < R82 take 28, < R82.10 take 28, < R82.20 take 29)
  - Multi-Domain Security Management Server (< R81.20 take 28, < R82 take 28, < R82.10 take 28, < R82.20 take 29)
  - Security Management Server (< R81.20 take 28, < R82 take 28, < R82.10 take 28, < R82.20 take 29)
  - Security Management Server
  - Log Server
cves:
  - id: CVE-2026-91843
    cvss: 9.8
references:
  - https://support.checkpoint.com/results/sk/sk1000155
  - https://www.cve.org/CVERecord?id=CVE-2026-91843
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1193/
  - https://cyber.gc.ca/en/alerts-advisories/check-point-security-advisory-av26-933
  - https://thehackernews.com/2026/09/critical-check-point-management-server.html
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit security management logs for username length error patterns
      owner: SOC
      due: 24h
      evidence: 'Checkpoint recommends searching, via SmartConsole, the pattern ''Administrator failed to log in: Username too long'''
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected Check Point servers to minimum take versions
      owner: IT Operations
      addresses: CVE-2026-91843
      evidence: Bulletin de sécurité Check Point sk1000155
updates:
  - at: "2026-09-18T04:24:18Z"
    level: L1
    summary: new product
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/09/critical-check-point-management-server.html
---

On September 16, 2026, Check Point released security advisory sk1000155 addressing a critical remote code execution (RCE) vulnerability, tracked as CVE-2026-91843. The vulnerability affects various Security Management and Log Server deployments, including Multi-Domain environments. Successful exploitation allows an unauthenticated remote attacker to execute arbitrary code on the affected appliance. Defenders should audit logs for specific indicators of failed authentication attempts associated with username length anomalies.

## Impact

Successful exploitation of CVE-2026-91843 results in total system compromise, enabling attackers to gain control over security management infrastructure, access sensitive logs, and potentially pivot into the protected network segments managed by the affected Check Point gateways. Organizations using Security Management Servers or Log Servers are at risk of complete administrative takeover.

## Recommendation

1. Patch all affected Check Point Security Management and Log Server instances by upgrading to the minimum version requirements specified in the vendor advisory (e.g., R81.20 take 28, R82 take 28, R82.10 take 28, or R82.20 take 29).
2. Perform a retrospective audit of SmartConsole Audit and Admin login logs to identify the string "Administrator failed to log in: Username too long", which may indicate reconnaissance or exploitation attempts.
3. Ensure all administrative management interfaces are restricted to trusted, segmented management networks and not exposed to the public internet.
