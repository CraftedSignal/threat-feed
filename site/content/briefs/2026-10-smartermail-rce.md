---
brief_id: brief-2026-10-23-smartermail-rce
event_id: brief-2026-10-23-smartermail-rce
revision: 2
activity_at: "2026-10-24T03:04:34Z"
revision_history:
  - revision: 2
    at: "2026-10-24T03:04:34Z"
    checksum: sha256:d3781f37b4c123af375db9985bbe44c06c4082f3c9558f633a59fb8b4211219d
    summary: 'added detection rule: Detect CVE-2026-24423 Exploitation - Unauthenticated ConnectToHub Access'
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - priority_score
      - priority_signals
      - references
      - rules
      - tags
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AAVAMIN-CVE-2026-24423&utm_source=rss&utm_medium=rss
title: 'SmarterTools SmarterMail: Unauthenticated remote code execution (CVE-2025-52691)'
slug: 2026-10-smartermail-rce
description: CVE-2025-52691 is a critical arbitrary file upload vulnerability in SmarterMail (Build 9406 and earlier) that enables unauthenticated remote code execution, with multiple proof-of-concept exploits publicly available.
date: "2026-10-23T20:48:03Z"
lastmod: "2026-10-24T03:03:52Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified against CVE-2025-52691 advisory context.
cpes:
  - cpe:2.3:a:smartertools:smartermail:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - file-upload
  - vulnerability
  - cve
  - cve-2026-24423
  - ssrf
  - rce
  - webserver
vendors:
  - SmarterTools
products:
  - SmarterMail (< 100.0.9413)
  - SmarterMail (< 100.0.9511)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can upload arbitrary files to any location on the mail server, potentially enabling remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Unauthenticated remote code execution via ConnectToHub by supplying a hubAddress that causes the target to load a malicious hub.
    confidence_band: high
cves:
  - id: CVE-2025-52691
    cvss: 10
    epss: 0.85655
    kev_status: "false"
  - id: CVE-2026-24423
    cvss: 9.8
    epss: 0.88177
    kev_status: "false"
references:
  - https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2025-124
  - https://nvd.nist.gov/vuln/detail/CVE-2025-52691
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RXERIUM-CVE-2025-52691&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AAVAMIN-CVE-2026-24423
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AAVAMIN-CVE-2026-24423&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-24423 Exploitation - Unauthenticated ConnectToHub Access
    description: Detects HTTP POST requests to the SmarterMail ConnectToHub API endpoint, which is the entry point for CVE-2026-24423.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch SmarterMail to version 100.0.9413 or later.
      owner: IT Operations
      due: 24h
      evidence: Affected Smartertools Smartermail versions < 100.0.9413.
    - action: Patch SmarterMail to 100.0.9511 or later
      owner: IT Operations
      due: 24h
      evidence: Vulnerability exists in versions < 100.0.9511
    - action: Enable webserver logging and apply detection rule
      owner: SOC
      due: 24h
      evidence: Exploit PoC requires POST access to the ConnectToHub endpoint
  hunt_leads:
    - lead: Identify unauthorized file uploads or abnormal file creation events in SmarterMail application directories.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - File system modification logs (FIM)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: SmarterMail Build 9406 and earlier is vulnerable to arbitrary file upload.
    - lead: Identify successful exploitation by looking for unexpected outbound network connections from the SmarterMail server to arbitrary internet-facing IPs following a request to the vulnerable endpoint.
      technique_id: T1190
      data_needed:
        - Process-to-network correlation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability is an SSRF, meaning the application will make an outbound request to the address provided in the hubAddress field.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to SmarterMail Build 100.0.9413.
      owner: IT Operations
      addresses: CVE-2025-52691
      evidence: Affected Smartertools Smartermail versions < 100.0.9413.
    - priority: immediate
      action: Apply network egress rules to block SmarterMail server from initiating outbound connections to non-essential external hosts.
      owner: IT Operations
      addresses: CVE-2026-24423
      evidence: The exploit relies on SSRF, which can be mitigated by restricting network connectivity.
updates:
  - at: "2026-10-24T03:03:52Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-24423 Exploitation - Unauthenticated ConnectToHub Access'
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AAVAMIN-CVE-2026-24423&utm_source=rss&utm_medium=rss
---

SmarterMail Build 9406 and earlier contains an unauthenticated arbitrary file upload vulnerability (CVE-2025-52691). The vulnerability allows an attacker to upload arbitrary files to any location on the mail server, which can be leveraged to achieve remote code execution. Public exploit code for this vulnerability is actively circulating on platforms such as GitHub and KitPloit. 

## Impact
Successful exploitation allows an unauthenticated attacker to gain remote code execution on the mail server with high privileges (CVSS 10.0).

## Recommendation
- Upgrade SmarterMail to Build 9413 or later immediately to remediate CVE-2025-52691.
- Audit web server access logs for anomalous POST requests directed at SmarterMail file upload endpoints.
- Restrict internet exposure of SmarterMail management interfaces where possible.
