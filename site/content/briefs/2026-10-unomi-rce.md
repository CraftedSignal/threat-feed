---
brief_id: brief-2026-10-24-unomi-rce
event_id: brief-2026-10-24-unomi-rce
revision: 1
activity_at: "2026-10-24T06:08:30Z"
title: 'Apache Unomi: Remote Code Execution via MVEL/OGNL Injection (CVE-2020-13942)'
slug: 2026-10-unomi-rce
description: Apache Unomi versions prior to 1.5.2 are vulnerable to remote code execution (RCE) via crafted MVEL or OGNL expressions injected into the /context.json endpoint.
date: "2026-10-24T06:08:30Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of detection rules
cpes:
  - cpe:2.3:a:apache:unomi:*:*:*:*:*:*:*:*
tags:
  - apache-unomi
  - rce
  - expression-injection
  - cve-2020-13942
vendors:
  - Apache
products:
  - Unomi (< 1.5.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: In versions prior to Apache Unomi 1.5.1, an attacker can send malicious requests using carefully crafted MVEL or OGNL expressions, causing the Unomi server to execute arbitrary code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: Execute system commands remotely
    confidence_band: high
cves:
  - id: CVE-2020-13942
    cvss: 9.8
    epss: 0.68296
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-YAUNSKY-UNOMI-CVE-2020-13942
  - https://github.com/vulhub/vulhub/tree/master/unomi/CVE-2020-13942
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-YAUNSKY-UNOMI-CVE-2020-13942&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2020-13942 Exploitation - MVEL/OGNL Injection in /context.json
    description: Detects exploitation attempts against CVE-2020-13942 by identifying suspicious characters or expression language patterns within the query or body of requests to /context.json.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory Apache Unomi instances and patch to 1.5.2 or later
      owner: IT Operations
      due: 24h
      evidence: Affected Versions Apache Unomi < 1.5.2
  hunt_leads:
    - lead: Search logs for successful exploitation attempts followed by network connection from Java processes
      technique_id: T1190
      data_needed:
        - Web access logs
        - Process creation logs (Java process spawning /bin/sh or cmd.exe)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Features 2. Reverse shell
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Apache Unomi 1.5.2
      owner: IT Operations
      addresses: CVE-2020-13942
      evidence: Affected Versions Apache Unomi < 1.5.2
---

Apache Unomi versions prior to 1.5.2 contain a remote code execution vulnerability (CVE-2020-13942) that allows unauthenticated attackers to execute arbitrary code via malicious MVEL or OGNL expressions. The vulnerability is triggered by sending a crafted request to the /context.json endpoint, specifically targeting the parameterValue field. Publicly available exploit scripts now exist that support remote command execution and reverse shell capabilities.

## Impact
Successful exploitation allows for full remote code execution on the underlying server, potentially leading to total system compromise, data exfiltration, and lateral movement within the network.

## Recommendation
- Update Apache Unomi to version 1.5.2 or later immediately.
- Implement strict ingress filtering for the /context.json endpoint to block unauthorized or external access.
- Monitor web server access logs for anomalous POST requests to /context.json containing expression language syntax (e.g., MVEL, OGNL) or shell metacharacters.
- Deploy the provided detection rule to identify exploitation attempts.
