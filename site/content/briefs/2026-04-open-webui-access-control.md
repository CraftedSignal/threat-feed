---
title: Open WebUI Broken Access Control Vulnerability (CVE-2026-34222)
slug: 2026-04-open-webui-access-control
description: A broken access control vulnerability in Open WebUI versions prior to 0.8.11 (CVE-2026-34222) allows authenticated users to potentially access or modify tool values they should not be authorized to, leading to privilege escalation and unauthorized configuration changes.
date: "2026-04-01T18:16:29Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - broken-access-control
  - web-application
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1212
    technique_name: Exploitation of Credentials
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2026-34222
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34222
  - https://github.com/open-webui/open-webui/releases/tag/v0.8.11
  - https://github.com/open-webui/open-webui/security/advisories/GHSA-7429-hxcv-268m
rules:
  - title: Detect Open WebUI Tool Value Modification
    description: Detects suspicious POST requests to modify tool values in Open WebUI, indicating a potential broken access control exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Open WebUI Unauthorized Configuration Change
    description: Detects potential unauthorized configuration changes in Open WebUI by monitoring for specific API calls.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Open WebUI is a self-hosted artificial intelligence platform designed to operate entirely offline. Prior to version 0.8.11, a broken access control vulnerability, identified as CVE-2026-34222, exists within the application concerning tool values. An authenticated user with low privileges could potentially manipulate these tool values, leading to unintended functionality or unauthorized access to sensitive configurations. The vulnerability was reported by GitHub, Inc. and patched in version 0.8.11. Exploitation requires an existing user account. The impact could allow an attacker to reconfigure the AI platform or access unauthorized tools.

## Attack Chain

1. An attacker gains a low-privileged account on the Open WebUI platform, either by registering an account if allowed or compromising an existing user.
2. The attacker analyzes the Open WebUI web application to identify the API endpoints or data structures used to manage "tool values."
3. The attacker crafts malicious HTTP requests targeting the "tool values" API endpoint, attempting to modify a tool value associated with a higher-privileged function or user.
4. Due to the broken access control, the application fails to properly validate if the attacker's account has the authorization to modify the target tool value.
5. The attacker successfully modifies the tool value.
6. The attacker triggers the functionality associated with the modified tool value.
7. The application executes the functionality with the modified tool value, potentially granting the attacker unauthorized access.
8. The attacker leverages this access to escalate privileges within the system, for example, by executing commands with elevated permissions or accessing sensitive data.

## Impact

Successful exploitation of this vulnerability allows an attacker with a low-privileged account to bypass intended access controls within the Open WebUI platform. This could allow unauthorized modifications to the AI platform's configuration, access to restricted tools or features, and potentially lead to complete compromise of the system. The CVE has a CVSS v3.1 score of 7.7, indicating a high severity. The number of potential victims is dependent on the deployment size of vulnerable Open WebUI instances.

## Recommendation

*   Upgrade Open WebUI to version 0.8.11 or later to patch the CVE-2026-34222 vulnerability.
*   Implement the Sigma rule "Detect Open WebUI Tool Value Modification" to monitor for suspicious activity related to tool value changes.
*   Review and enforce strict access control policies within the Open WebUI application to minimize the impact of potential access control vulnerabilities.
*   Monitor web server logs for suspicious POST requests to API endpoints associated with tool configuration and management, as indicated in the attack chain.
