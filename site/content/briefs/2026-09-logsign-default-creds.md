---
title: Default Credential Vulnerability in Logsign SIEM
slug: 2026-09-logsign-default-creds
description: Logsign SIEM versions 6.4.101 through 6.4.116 contain a critical default credential vulnerability that permits unauthorized access via known usernames and passwords.
date: "2026-09-28T16:20:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:innotim:logsign_siem:6.4.101:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication
  - siem
vendors:
  - Innotim
products:
  - Logsign SIEM (6.4.101 to <6.4.117)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Logsign SIEM allows Try Common or Default Usernames and Passwords.
    confidence_band: high
cves:
  - id: CVE-2026-90924
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90924
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Logsign SIEM to version 6.4.117 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-90924 requires upgrade to version 6.4.117
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the Logsign SIEM web interface to authorized management subnets only
      owner: SOC
      addresses: CVE-2026-90924
      evidence: Source identifies default credential vulnerability
---

Logsign SIEM, developed by Innotim Software, Telecommunications and Consultancy Trade Ltd. Co., contains a critical vulnerability identified as CVE-2026-90924. This vulnerability arises from the use of default credentials within the application, allowing an attacker to bypass authentication mechanisms by leveraging common or default usernames and passwords. The scope of this issue affects product versions from 6.4.101 up to, but not including, 6.4.117. Given that SIEM platforms often ingest sensitive logs and hold administrative privileges across an organization's network, unauthorized access via this flaw could lead to full platform compromise, data exfiltration, or the tampering of security audit trails. Organizations running affected versions are at high risk of unauthenticated access by remote adversaries who identify the SIEM instance.

## Impact

Successful exploitation of this vulnerability grants an attacker unauthorized administrative access to the Logsign SIEM interface. In a security operations context, this allows an adversary to view sensitive security telemetry, disable alerting, modify correlation rules, or gain pivot points into the broader internal infrastructure. As Logsign SIEM is a centralized repository for enterprise security data, compromise results in a loss of visibility and integrity for the entire SOC ecosystem.

## Recommendation

Prioritize the immediate upgrade of all Logsign SIEM installations to version 6.4.117 or later to address CVE-2026-90924. If an immediate upgrade is not feasible, restrict network access to the SIEM management interface to authorized administrative segments only. Audit current user accounts for unauthorized modifications or unexpected login patterns from external IP addresses. Monitor web server logs for high-frequency login attempts directed at the SIEM administrative interface.
