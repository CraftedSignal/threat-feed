---
brief_id: brief-2026-10-22-gitlab-rce
event_id: brief-2026-10-22-gitlab-rce
revision: 1
activity_at: "2026-10-05T18:41:35Z"
title: 'GitLab CE/EE: Unauthenticated remote code execution (CVE-2026-110264)'
slug: 2026-10-gitlab-rce
description: An integer overflow vulnerability in GitLab CE/EE allows unauthenticated attackers to execute arbitrary code via specially crafted regular expressions.
date: "2026-10-05T18:41:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Checked against NVD content
cpes:
  - cpe:2.3:a:gitlab:ce_ee:*:*:*:*:*:*:*:*
tags:
  - cve
  - rce
  - vulnerability
  - gitlab
vendors:
  - GitLab
products:
  - GitLab CE/EE (7.0 - 18.11.12)
  - GitLab CE/EE (19.0.0 - 19.0.9)
  - GitLab CE/EE (19.1.0 - 19.1.8)
  - GitLab CE/EE (19.2.0 - 19.2.8)
  - GitLab CE/EE (19.3.0 - 19.3.5)
  - GitLab CE/EE (19.4.0 - 19.4.2)
  - GitLab CE/EE (19.5.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An issue has been discovered in GitLab CE/EE that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server.
    confidence_band: high
cves:
  - id: CVE-2026-110264
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110264
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch GitLab CE/EE to the fixed versions (18.11.13, 19.0.10, 19.1.9, 19.2.9, 19.3.6, 19.4.3, or 19.5.1).
      owner: IT Operations
      due: 24h
      evidence: Vulnerability necessitates urgent patching to prevent RCE.
  mitigation_plan:
    - priority: immediate
      action: Upgrade GitLab CE/EE to 18.11.13 or later
      owner: IT Operations
      addresses: CVE-2026-110264
      evidence: Source advises patching across specified version branches.
---

A critical integer overflow vulnerability (CVE-2026-110264) exists in GitLab CE/EE, enabling unauthenticated remote code execution. The vulnerability is triggered when the application processes a specially crafted regular expression. This issue affects multiple GitLab release branches: versions 7.0 through 18.11.12, 19.0.0 through 19.0.9, 19.1.0 through 19.1.8, 19.2.0 through 19.2.8, 19.3.0 through 19.3.5, 19.4.0 through 19.4.2, and 19.5.0.

## Impact
Successful exploitation allows an unauthenticated attacker to execute arbitrary code on the underlying GitLab server, typically resulting in full system compromise.

## Recommendation
- Upgrade GitLab CE/EE instances immediately to the patched versions: 18.11.13, 19.0.10, 19.1.9, 19.2.9, 19.3.6, 19.4.3, or 19.5.1.
- Audit web server access logs for anomalous, high-complexity, or exceptionally long regex patterns being submitted to application endpoints.
- Restrict access to administrative or high-risk GitLab endpoints to trusted internal networks until patching is completed.
