---
title: OpenClaw Privilege Escalation Vulnerability (CVE-2026-62194)
slug: 2026-07-openclaw-privilege-escalation
description: CVE-2026-62194 is a high-severity privilege escalation vulnerability in OpenClaw versions prior to 2026.6.9, allowing lower-trust callers to execute or persist actions with elevated privileges through exploited plugin install commands.
date: "2026-07-13T22:26:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw versions 2026.5.20 before 2026.6.9
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: OpenClaw versions 2026.5.20 before 2026.6.9 contain a privilege escalation vulnerability in plugin install commands that allows lower-trust callers to execute or persist actions beyond their intended authorization.
    confidence_band: high
cves:
  - id: CVE-2026-62194
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62194
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-7vrr-rp4x-4g76
  - https://www.vulncheck.com/advisories/openclaw-privilege-escalation-via-plugin-install
iocs:
  - type: url
    value: https://github.com/openclaw/openclaw/security/advisories/GHSA-7vrr-rp4x-4g76
  - type: url
    value: https://www.vulncheck.com/advisories/openclaw-privilege-escalation-via-plugin-install
ioc_counts:
  url: 2
---

A high-severity privilege escalation vulnerability, tracked as CVE-2026-62194, affects OpenClaw versions 2026.5.20 before 2026.6.9. This flaw exists within the plugin install commands functionality, enabling lower-trust callers to execute or persist actions beyond their intended authorization. Attackers can exploit misconfigured input paths or enabled features to escalate privileges and perform unauthorized actions when the vulnerable feature is reachable. This allows an authenticated, low-privileged attacker to gain higher access rights within the OpenClaw application. Defenders should prioritize patching and closely monitor for any unusual plugin installation activities or actions originating from accounts with limited privileges within their OpenClaw deployments.

## Attack Chain

1. An authenticated, low-privileged attacker gains access to the OpenClaw application.
2. The attacker identifies a misconfigured input path or enabled feature within the application's plugin install commands that can be leveraged for privilege escalation.
3. The attacker crafts a malicious plugin installation command designed to exploit the CVE-2026-62194 vulnerability.
4. The attacker executes the specially crafted plugin installation command as a low-privileged user.
5. Due to the vulnerability in OpenClaw, the plugin install command is processed and executed with elevated privileges, bypassing authorization checks.
6. The attacker successfully escalates privileges within the OpenClaw application, gaining control typically reserved for higher-trust users.
7. Using the escalated privileges, the attacker performs unauthorized actions, which may include executing arbitrary code, modifying critical configurations, or establishing persistence.

## Impact

Successful exploitation of CVE-2026-62194 grants a low-privileged attacker the ability to escalate privileges within OpenClaw, potentially leading to full control over the application. This can result in unauthorized data access, modification, or deletion, system compromise, or the execution of arbitrary code within the application's environment. The vulnerability impacts organizations utilizing affected versions of OpenClaw, with the severity of impact depending on the role and criticality of the OpenClaw instance within the targeted environment.

## Recommendation

* Upgrade all OpenClaw installations to version 2026.6.9 or newer immediately to mitigate CVE-2026-62194.
* Review the configuration of plugin install commands and related input paths in OpenClaw to ensure they are not misconfigured, as referenced in the NVD advisory for CVE-2026-62194.
* Implement robust monitoring for unusual plugin installation activities or any actions originating from lower-privileged accounts that suggest privilege escalation within OpenClaw environments.
