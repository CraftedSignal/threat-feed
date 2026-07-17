---
title: CVE-2026-62223 OpenClaw Authorization Bypass Vulnerability
slug: 2026-07-openclaw-auth-bypass
description: OpenClaw versions prior to 2026.5.18 are vulnerable to an authorization bypass (CVE-2026-62223) within its device-pair approval feature, allowing lower-trust callers to execute actions beyond their intended permissions by exploiting misconfigured input paths, leading to unauthorized actions or persistence if the feature is enabled and reachable.
date: "2026-07-17T02:31:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - vulnerability
  - openclaw
  - cve
vendors:
  - OpenClaw
products:
  - OpenClaw (< 2026.5.18)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allows lower-trust callers to execute actions beyond their intended authorization
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Attackers can exploit misconfigured input paths to execute or persist unauthorized actions
    confidence_band: high
cves:
  - id: CVE-2026-62223
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62223
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-hx85-fgcw-9vrc
  - https://www.vulncheck.com/advisories/openclaw-authorization-bypass-via-device-pair
---

A critical authorization bypass vulnerability, identified as CVE-2026-62223, affects OpenClaw software versions prior to 2026.5.18. This flaw resides within the application's device-pair approval feature, enabling attackers with lower trust privileges to execute actions that should be restricted. By exploiting misconfigured input paths when the device-pair approval feature is active and accessible, malicious actors can circumvent intended security controls. This vulnerability allows for the execution of unauthorized actions or the establishment of persistence mechanisms within the compromised system, posing a significant risk to the integrity and confidentiality of data. Organizations using affected OpenClaw versions are urged to update immediately to mitigate potential exploitation.

## Attack Chain

1. Attacker identifies a vulnerable OpenClaw instance running a version prior to 2026.5.18.
2. The attacker confirms that the "device-pair approval" feature is enabled and reachable on the target OpenClaw deployment.
3. A specialized request is crafted by the attacker, targeting known or inferred "misconfigured input paths" within the device-pair approval feature.
4. The crafted request bypasses the authorization checks implemented in OpenClaw, due to the presence of CVE-2026-62223.
5. OpenClaw processes the attacker's request, granting the attacker the ability to execute actions normally reserved for higher-privileged users or processes.
6. The attacker leverages this unauthorized access to perform privileged actions, such as gaining access to sensitive data or modifying system configurations.
7. The attacker may establish "persistence" on the system through their newly acquired unauthorized capabilities to maintain access.

## Impact

Successful exploitation of CVE-2026-62223 can lead to severe consequences for organizations utilizing OpenClaw. Attackers gaining unauthorized access can execute actions beyond their legitimate permissions, potentially leading to data breaches, system compromise, or service disruption. The CVSS 3.1 base score of 8.8 (High) indicates a high impact on confidentiality, integrity, and availability. While specific victim counts or targeted sectors are not detailed, any organization running affected OpenClaw versions with the vulnerable feature enabled is at risk of significant operational and security damage.

## Recommendation

* Patch CVE-2026-62223 immediately by upgrading OpenClaw to version 2026.5.18 or later. Refer to the GitHub and VulnCheck advisories in the references.
* Review and secure configurations of OpenClaw's device-pair approval feature to ensure all input paths are correctly configured and authorization checks are robust.
