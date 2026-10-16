---
title: Authorization Bypass in sshportal Management Shell
slug: 2026-10-sshportal-auth-bypass
description: An authorization vulnerability in the sshportal management shell allows authenticated non-admin users to retrieve decrypted backend private SSH keys and bypass access controls.
date: "2026-10-16T18:47:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sshportal:sshportal:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - authentication-bypass
vendors:
  - sshportal
products:
  - sshportal (<= 1.19.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation of Privilege Escalation Vulnerability
    evidence: sshportal through 1.19.5 contains a missing authorization vulnerability in the management shell 'key show' command that allows authenticated non-admin users to obtain decrypted backend private SSH keys.
    confidence_band: high
cves:
  - id: CVE-2026-111638
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111638
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade sshportal to the first version released after 1.19.5.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-111638 impacts sshportal through 1.19.5.
  mitigation_plan:
    - priority: immediate
      action: Rotate backend SSH keys that were configured in sshportal.
      owner: IT Operations
      addresses: CVE-2026-111638
      evidence: The vulnerability allows unauthorized retrieval of decrypted backend keys.
---

sshportal versions 1.19.5 and earlier are affected by a missing authorization vulnerability within the management shell component, specifically tied to the 'key show' command. This flaw permits authenticated users, who lack administrative privileges, to successfully request and view decrypted backend private SSH keys. By querying for predictable key identifiers, such as 'default' or 'host', an attacker can extract sensitive credentials used by the system to communicate with backend infrastructure. The exposure of these keys effectively negates the security posture of the platform, as it permits the attacker to establish direct connections to backend hosts, thereby circumventing configured access control lists (ACLs) and evading centralized session recording mechanisms. This vulnerability (CVE-2026-111638) highlights a critical failure in enforcing role-based access control within the management interface.

## Impact

Successful exploitation of CVE-2026-111638 allows unauthorized lateral movement and direct access to backend systems. This bypasses the security auditing and recording features of the sshportal gateway, creating a significant risk of data exfiltration and persistent unauthorized access to managed infrastructure. Organizations relying on sshportal to broker access to critical backend assets are at risk of complete compromise of these assets if any authenticated user account is hijacked or malicious.

## Recommendation

- Upgrade sshportal to the latest patched version beyond 1.19.5 immediately to remediate CVE-2026-111638.
- Audit logs for the management shell interface to identify anomalous 'key show' command usage by non-administrative user accounts.
- Review and rotate any backend private SSH keys that may have been accessible to non-admin users during the period of exposure.
