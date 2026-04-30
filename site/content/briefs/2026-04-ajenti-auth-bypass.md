---
title: Ajenti Authorization Bypass Vulnerability (CVE-2026-35175)
slug: 2026-04-ajenti-auth-bypass
description: Ajenti versions before 2.2.15 contain an authorization bypass vulnerability that allows authenticated non-superuser users to install custom packages, potentially leading to privilege escalation and system compromise.
date: "2026-04-03T03:57:43Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - ajenti
  - authorization-bypass
  - privilege-escalation
  - CVE-2026-35175
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-73jv-44c3-j5p2
  - https://github.com/ajenti/ajenti/releases/tag/v2.2.15
rules:
  - title: Detect Suspicious Ajenti Package Installation
    description: Detects potential exploitation of Ajenti authorization bypass vulnerability through monitoring of custom package installations.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Package Installation via Auth Bypass
    description: Detects unauthorized package installations in Ajenti, indicative of a potential auth bypass. This will need tuning to account for authorized users who can install packages.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Ajenti is a web-based system administration panel. Prior to version 2.2.15, a flaw exists in the `auth_users` authentication plugin that permits authenticated users lacking superuser privileges to install custom packages. This vulnerability, identified as CVE-2026-35175, allows a low-privileged user to bypass intended authorization checks, potentially escalating their privileges and compromising the entire system. An attacker could leverage this vulnerability to install malicious packages, execute arbitrary code with elevated privileges, and gain unauthorized access to sensitive data or system functionalities. Organizations using vulnerable versions of Ajenti are at risk of internal privilege escalation attacks.

## Attack Chain

1. An attacker gains initial access to the Ajenti web panel with a valid, non-superuser account using the `auth_users` plugin.
2. The attacker navigates to the custom package installation feature within the Ajenti web interface.
3. The attacker uploads a malicious custom package designed to execute arbitrary commands or install backdoors.
4. Ajenti fails to properly validate the user's privileges before initiating the package installation process.
5. The malicious package is installed with the privileges of the Ajenti process, which may include elevated permissions.
6. The malicious package executes its payload, potentially installing a reverse shell, creating new administrative accounts, or modifying critical system files.
7. The attacker leverages the installed backdoor or elevated privileges to gain persistent access to the system.

## Impact

Successful exploitation of this vulnerability allows an authenticated, non-superuser user to execute arbitrary code with elevated privileges. This can lead to full system compromise, data theft, and disruption of services. While the precise number of affected installations is unknown, any organization running Ajenti versions prior to 2.2.15 with the `auth_users` authentication plugin enabled is vulnerable. The impact includes potential data breaches, system downtime, and reputational damage.

## Recommendation

*   Immediately upgrade Ajenti to version 2.2.15 or later to patch CVE-2026-35175 (see References).
*   Implement the Sigma rule `Detect Suspicious Ajenti Package Installation` to detect unauthorized package installations.
*   Review Ajenti access logs for unusual activity or attempts to access restricted functionalities.
