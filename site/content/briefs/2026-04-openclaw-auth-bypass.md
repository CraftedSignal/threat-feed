---
title: OpenClaw Authentication Bypass in Remote Onboarding
slug: 2026-04-openclaw-auth-bypass
description: OpenClaw before 2026.3.28 contains an authentication bypass vulnerability (CVE-2026-41342) in the remote onboarding component, allowing attackers to spoof discovery endpoints and capture gateway credentials or traffic.
date: "2024-01-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - authentication bypass
  - remote onboarding
  - credential theft
  - cve-2026-41342
vendors:
  - openclaw
products:
  - openclaw
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-41342
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41342
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-3cw3-5vxw-g2h3
  - https://www.vulncheck.com/advisories/openclaw-unauthenticated-discovery-endpoint-credential-exfiltration-via-remote-onboarding
rules:
  - title: Detect Connection to Suspicious Onboarding Discovery Endpoint
    description: Detects connections to unusual or potentially malicious discovery endpoints during remote onboarding, indicating possible spoofing attempts related to CVE-2026-41342.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
  - title: Detect OpenClaw Process Connecting to Non-Standard Ports
    description: This rule identifies OpenClaw processes establishing network connections to ports commonly associated with malicious activity, potentially indicating exploitation or command and control.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

OpenClaw, a software solution, is vulnerable to an authentication bypass flaw in versions prior to 2026.3.28. Specifically, the remote onboarding component persists unauthenticated discovery endpoints without requiring explicit trust confirmation. This vulnerability, identified as CVE-2026-41342, enables a threat actor to spoof legitimate discovery endpoints. By doing so, attackers can redirect the onboarding process toward malicious gateways under their control. This redirection allows the attacker to intercept and capture gateway credentials or monitor sensitive network traffic. This is a critical vulnerability because successful exploitation allows an attacker to gain unauthorized access to a target system and potentially escalate privileges.

## Attack Chain

1.  Attacker identifies a vulnerable OpenClaw instance running a version before 2026.3.28.
2.  The attacker spoofs a legitimate discovery endpoint using a malicious server.
3.  A new or existing user attempts to onboard remotely through the OpenClaw application.
4.  The application, lacking proper authentication checks, connects to the attacker's spoofed discovery endpoint.
5.  The spoofed endpoint redirects the onboarding process to a malicious gateway controlled by the attacker.
6.  The user unknowingly provides their gateway credentials to the malicious gateway.
7.  The attacker captures the user's gateway credentials or intercepts subsequent network traffic.
8.  The attacker leverages the stolen credentials to gain unauthorized access to the OpenClaw system or other related resources.

## Impact

Successful exploitation of CVE-2026-41342 can lead to credential compromise and unauthorized access to sensitive systems and data. An attacker who successfully spoofs a discovery endpoint can steal gateway credentials, enabling them to impersonate legitimate users and perform malicious actions within the OpenClaw environment. The impact is significant for organizations relying on OpenClaw for secure remote onboarding, potentially leading to data breaches, service disruption, and reputational damage.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.28 or later to patch CVE-2026-41342 and mitigate the authentication bypass vulnerability.
*   Implement network monitoring to detect and alert on connections to unexpected or untrusted discovery endpoints. Consider deploying a network connection rule like the one below to detect suspicious connections during onboarding.
*   Review and strengthen the onboarding process to include multi-factor authentication and explicit trust confirmation for discovery endpoints.
