---
brief_id: brief-2026-10-23-smartermail-rce
event_id: brief-2026-10-23-smartermail-rce
revision: 1
activity_at: "2026-10-23T20:48:03Z"
title: 'SmarterTools SmarterMail: Unauthenticated remote code execution (CVE-2025-52691)'
slug: 2026-10-smartermail-rce
description: CVE-2025-52691 is a critical arbitrary file upload vulnerability in SmarterMail (Build 9406 and earlier) that enables unauthenticated remote code execution, with multiple proof-of-concept exploits publicly available.
date: "2026-10-23T20:48:03Z"
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
vendors:
  - SmarterTools
products:
  - SmarterMail (< 100.0.9413)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can upload arbitrary files to any location on the mail server, potentially enabling remote code execution.
    confidence_band: high
cves:
  - id: CVE-2025-52691
    cvss: 10
    epss: 0.85655
    kev_status: "false"
references:
  - https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2025-124
  - https://nvd.nist.gov/vuln/detail/CVE-2025-52691
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RXERIUM-CVE-2025-52691&utm_source=rss&utm_medium=rss
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
  mitigation_plan:
    - priority: immediate
      action: Upgrade to SmarterMail Build 100.0.9413.
      owner: IT Operations
      addresses: CVE-2025-52691
      evidence: Affected Smartertools Smartermail versions < 100.0.9413.
---

SmarterMail Build 9406 and earlier contains an unauthenticated arbitrary file upload vulnerability (CVE-2025-52691). The vulnerability allows an attacker to upload arbitrary files to any location on the mail server, which can be leveraged to achieve remote code execution. Public exploit code for this vulnerability is actively circulating on platforms such as GitHub and KitPloit. 

## Impact
Successful exploitation allows an unauthenticated attacker to gain remote code execution on the mail server with high privileges (CVSS 10.0).

## Recommendation
- Upgrade SmarterMail to Build 9413 or later immediately to remediate CVE-2025-52691.
- Audit web server access logs for anomalous POST requests directed at SmarterMail file upload endpoints.
- Restrict internet exposure of SmarterMail management interfaces where possible.
