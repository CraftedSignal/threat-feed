---
title: JuggleIM im-server Hardcoded Administrator Credentials
slug: 2026-10-juggleim-default-creds
description: JuggleIM im-server versions through 1.8.16 contain a hardcoded administrator account that allows unauthenticated remote attackers to gain full administrative access to tenant applications and secrets via the console on port 8090.
date: "2026-10-15T22:41:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:juggleim:im-server:*:*:*:*:*:*:*:*
vendors:
  - JuggleIM
products:
  - im-server (<= 1.8.16)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: JuggleIM im-server through 1.8.16 ships default administrator credentials admin/123456 that allow unauthenticated remote attackers to access the admin console
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Attackers can log in as administrator, even after account deletion since CheckLogin recreates it
    confidence_band: high
cves:
  - id: CVE-2026-111329
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111329
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to TCP port 8090 to authorized networks
      owner: IT Operations
      due: 24h
      evidence: Source states console is accessible on port 8090
  mitigation_plan:
    - priority: immediate
      action: Upgrade JuggleIM im-server beyond version 1.8.16
      owner: IT Operations
      addresses: CVE-2026-111329
      evidence: NVD vulnerability entry
---

JuggleIM im-server versions 1.8.16 and earlier ship with default hardcoded administrator credentials (admin/123456). This vulnerability allows unauthenticated remote attackers to access the administrative console, which is typically exposed on port 8090. Once authenticated, an attacker gains complete control over tenant applications and sensitive application secrets. The issue is exacerbated by the application's CheckLogin logic, which automatically recreates the administrator account if it is deleted by a user, preventing effective remediation through account removal. This creates a persistent unauthorized access vector for any publicly exposed instance.

## Impact

Successful exploitation grants an attacker full administrative control over the JuggleIM im-server environment. This impact includes the unauthorized management of all hosted tenant applications and the exfiltration of critical application secrets. The vulnerability is considered highly severe (CVSS 9.8) because it allows for immediate, unauthenticated, and persistent compromise of sensitive messaging infrastructure.

## Recommendation

Immediate action is required to restrict access to the administrative console and update the software.

* Restrict network access to the administrative console on TCP port 8090 to authorized management IP addresses only, using firewall or network security group policies.
* Upgrade to a patched version of JuggleIM im-server where the hardcoded credential default has been removed.
* Monitor authentication logs for successful logins to the admin console using the username "admin".
* Conduct a review of all tenant application secrets and keys for potential compromise if the instance was exposed to the internet.
