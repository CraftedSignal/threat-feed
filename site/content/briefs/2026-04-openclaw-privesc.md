---
title: OpenClaw Privilege Escalation Vulnerability (CVE-2026-35669)
slug: 2026-04-openclaw-privesc
description: OpenClaw before 2026.3.25 contains a privilege escalation vulnerability in gateway-authenticated plugin HTTP routes due to incorrect scope minting, allowing attackers to gain elevated privileges and perform unauthorized administrative actions.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - openclaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35669
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35669
  - https://github.com/openclaw/openclaw/commit/ec2dbcff9afd8a52e00de054b506c91726d9fbbe
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-qm2m-28pf-hgjw
  - https://www.vulncheck.com/advisories/openclaw-privilege-escalation-via-gateway-plugin-http-authentication-scope
rules:
  - title: Detect Suspicious OpenClaw Admin Scope Minting
    description: Detects potential exploitation of OpenClaw CVE-2026-35669 by monitoring for requests where admin scope is assigned incorrectly.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Administrative Actions After Privilege Escalation
    description: Detects potential administrative actions after privilege escalation in OpenClaw
    platform: sigma
    severity: medium
    tactics:
      - impact
      - privilege_escalation
    techniques:
      - T1068
      - T1489
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, a yet-to-be-determined software application, is susceptible to a privilege escalation vulnerability (CVE-2026-35669) affecting versions prior to 2026.3.25. The vulnerability resides in gateway-authenticated plugin HTTP routes, where the system incorrectly assigns `operator.admin` runtime scope, irrespective of the scopes granted to the caller. This flaw enables attackers to bypass intended scope boundaries, potentially leading to the execution of unauthorized administrative tasks. The discovery of this vulnerability highlights the importance of robust access control mechanisms in OpenClaw and necessitates immediate patching to mitigate the risk of exploitation. Successful exploitation could lead to a complete compromise of the OpenClaw instance.

## Attack Chain

1. An attacker gains initial access with limited privileges to the OpenClaw system.
2. The attacker crafts a malicious HTTP request targeting a gateway-authenticated plugin HTTP route.
3. Due to the vulnerability (CVE-2026-35669), OpenClaw incorrectly mints the `operator.admin` runtime scope for the request, regardless of the attacker's actual permissions.
4. The attacker's request, now incorrectly granted administrative privileges, is processed by the affected plugin.
5. The attacker leverages the elevated privileges to perform unauthorized administrative actions.
6. The attacker may modify sensitive configurations, create new administrative accounts, or access restricted data.
7. The attacker maintains persistence by injecting malicious code or scripts into the OpenClaw system.
8. The attacker achieves complete control over the OpenClaw instance, potentially compromising the entire environment.

## Impact

Successful exploitation of CVE-2026-35669 can lead to significant damage. An attacker can gain full administrative control over OpenClaw, potentially affecting all users and systems managed by the software. Depending on the role of OpenClaw, this could result in data breaches, service disruptions, and financial losses. The vulnerability affects all deployments running OpenClaw versions prior to 2026.3.25, making it a critical concern for organizations using the affected software.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.25 or later to patch CVE-2026-35669.
*   Deploy the Sigma rule `Detect Suspicious OpenClaw Admin Scope Minting` to identify potential exploitation attempts targeting CVE-2026-35669.
*   Monitor web server logs for unusual activity on gateway-authenticated plugin HTTP routes, as this could indicate exploitation attempts.
*   Review and harden access control configurations in OpenClaw to limit the impact of potential privilege escalation attacks.
*   Enable logging for HTTP requests to identify the vulnerable routes using category "webserver" and product "linux" or "windows".
