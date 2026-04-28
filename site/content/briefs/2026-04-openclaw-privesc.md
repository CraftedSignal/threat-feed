---
title: OpenClaw Privilege Escalation Vulnerability (CVE-2026-41379)
slug: 2026-04-openclaw-privesc
description: OpenClaw before version 2026.3.28 contains a privilege escalation vulnerability, allowing authenticated operators with write permissions to modify sensitive Talk Voice configurations via the chat.send endpoint.
date: "2026-04-28T19:37:40Z"
severities:
  - high
tags:
  - privilege-escalation
  - cve
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41379
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41379
  - https://github.com/openclaw/openclaw/commit/e34694733fc64931ed4a543c73d84ad3435d5df1
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-3q42-xmxv-9vfr
  - https://www.vulncheck.com/advisories/openclaw-privilege-escalation-via-chat-send-to-admin-class-talk-voice-config
rules:
  - title: Detect OpenClaw Talk Voice Configuration Modification
    description: Detects modifications to Talk Voice configurations, potentially indicating exploitation of CVE-2026-41379.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1555.003
    data_sources:
      - webserver
      - linux
  - title: OpenClaw Chat Send Endpoint Activity
    description: Detects POST requests to the /chat.send endpoint, which could indicate an attempt to exploit CVE-2026-41379.
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

OpenClaw, prior to version 2026.3.28, is vulnerable to a privilege escalation. This vulnerability allows authenticated operators who possess write privileges to gain unauthorized access to and modify administrative-level Talk Voice configuration persistence settings. The vulnerability is located in the chat.send endpoint which should only be accessible to administrators. This could lead to unauthorized configuration changes, potentially disrupting services or compromising sensitive information. Exploitation requires valid operator credentials with write permissions.

## Attack Chain

1. An attacker obtains valid operator credentials with write privileges.
2. The attacker authenticates to the OpenClaw application using the compromised or malicious operator account.
3. The attacker crafts a malicious request targeting the chat.send endpoint.
4. The crafted request includes parameters designed to modify Talk Voice configuration settings, normally restricted to administrators.
5. The application incorrectly authorizes the request due to the vulnerability, allowing the operator to bypass intended access controls.
6. The sensitive voice configuration persistence is accessed and modified.
7. The attacker alters critical voice settings, potentially causing service disruption or data compromise.
8. The attacker achieves privilege escalation by modifying admin-level configurations, impacting overall system integrity.

## Impact

Successful exploitation of this vulnerability allows attackers with operator-level write access to modify critical Talk Voice configuration settings. This could lead to service disruptions, unauthorized data access, or other malicious activities. The vulnerability affects OpenClaw installations before version 2026.3.28, potentially impacting any organization using the vulnerable versions of the software. The consequences can range from minor inconveniences to significant security breaches, depending on the specific configurations modified.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.28 or later to patch CVE-2026-41379.
*   Implement the Sigma rule `Detect OpenClaw Talk Voice Configuration Modification` to monitor for unauthorized changes to voice configurations.
*   Review and enforce strict access control policies to limit operator privileges to the minimum necessary for their roles.
*   Monitor web server logs for suspicious activity targeting the `chat.send` endpoint, using the `OpenClaw Chat Send Endpoint Activity` Sigma rule.
