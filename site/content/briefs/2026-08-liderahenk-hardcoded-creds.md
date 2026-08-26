---
title: Hard-coded Credentials in Liderahenk Software
slug: 2026-08-liderahenk-hardcoded-creds
description: The Liderahenk software contains a hard-coded credentials vulnerability that allows unauthorized authentication via default account credentials, potentially leading to full system compromise.
date: "2026-08-26T16:20:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - TÜBİTAK BİLGEM
products:
  - Liderahenk
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110.001
    technique_name: 'Brute Force: Password Guessing'
    evidence: 'This issue affects Liderahenk: before 3.5.5.'
    confidence_band: high
cves:
  - id: CVE-2026-75896
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75896
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Liderahenk to version 3.5.5 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-75896 mitigation recommendation
  mitigation_plan:
    - priority: immediate
      action: Restrict management console network access
      owner: IT Operations
      addresses: CVE-2026-75896
      evidence: Hard-coded credentials facilitate unauthorized access
---

TÜBİTAK BİLGEM Software Technologies Research Institute has disclosed a critical security vulnerability, identified as CVE-2026-75896, affecting the Liderahenk management platform versions prior to 3.5.5. The vulnerability stems from the presence of hard-coded credentials within the application, which facilitates unauthorized access through the use of default or predictable usernames and passwords. This flaw carries a CVSS v3.1 base score of 9.1, indicating a high risk to organizational security. Given that Liderahenk is typically used for centralized management of enterprise systems, unauthorized access could allow an adversary to perform lateral movement, execute arbitrary code, or exfiltrate sensitive data from managed endpoints. Defenders must prioritize upgrading Liderahenk instances to version 3.5.5 or later to mitigate this risk.

## Impact

Successful exploitation of this vulnerability allows unauthenticated, remote attackers to gain unauthorized access to the Liderahenk management console. This level of access grants the attacker control over connected managed systems, potentially leading to widespread administrative privilege escalation, persistent access, and the compromise of entire network segments where the software is deployed.

## Recommendation

* Immediately upgrade all instances of Liderahenk to version 3.5.5 or later to resolve the hard-coded credential vulnerability.
* Audit all administrative access logs in the Liderahenk management console for successful logins originating from unauthorized or unexpected source IPs.
* Disable default administrative accounts if they are not required and ensure that all management console access is restricted via IP allowlisting or VPN requirements.
* Monitor network traffic originating from the Liderahenk server, as unauthorized access may be followed by lateral movement attempts into the wider network environment.
