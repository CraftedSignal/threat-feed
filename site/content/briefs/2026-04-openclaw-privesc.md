---
title: OpenClaw Privilege Escalation Vulnerability (CVE-2026-35663)
slug: 2026-04-openclaw-privesc
description: OpenClaw before 2026.3.25 contains a privilege escalation vulnerability (CVE-2026-35663) that allows non-admin operators to gain unauthorized administrative privileges by self-requesting broader scopes during backend reconnect and bypassing pairing requirements.
date: "2026-04-10T17:17:08Z"
severities:
  - high
tags:
  - privilege-escalation
  - cve-2026-35663
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35663
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35663
  - https://github.com/openclaw/openclaw/commit/d3d8e316bd819d3c7e34253aeb7eccb2510f5f48
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-9hjh-fr4f-gxc4
  - https://www.vulncheck.com/advisories/openclaw-privilege-escalation-via-backend-reconnect-scope-self-claim
rules:
  - title: Detect OpenClaw Privilege Escalation
    description: Detects attempts to escalate privileges in OpenClaw by requesting the operator.admin scope during backend reconnect.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Backend Reconnect Scope Modification
    description: Detects modifications to the scope parameter during an OpenClaw backend reconnect, potentially indicating privilege escalation attempts.
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

OpenClaw, a yet-to-be-identified application, is vulnerable to a privilege escalation flaw (CVE-2026-35663) in versions prior to 2026.3.25. The vulnerability allows a non-administrative operator to escalate their privileges to that of an administrator. This is achieved by manipulating the backend reconnect process to self-request broader scopes, specifically the `operator.admin` scope. The attacker bypasses the standard pairing requirements, allowing them to authenticate as an administrator without proper authorization. This vulnerability was reported on April 10, 2026, and poses a significant risk to OpenClaw deployments where proper access controls are critical. Successful exploitation grants unauthorized administrative access, potentially leading to full system compromise.

## Attack Chain

1.  A non-admin operator initiates a legitimate connection to the OpenClaw backend.
2.  The operator disconnects from the backend, triggering a reconnect sequence.
3.  During the reconnection attempt, the operator modifies the scope request to include `operator.admin`, a privileged scope.
4.  The application fails to properly validate the requested scope against the user's existing privileges.
5.  The backend grants the requested `operator.admin` scope due to insufficient authorization checks.
6.  The operator reconnects to the backend with the elevated administrative privileges.
7.  The attacker leverages the administrative privileges to perform unauthorized actions, such as modifying system configurations, accessing sensitive data, or creating new user accounts.

## Impact

Successful exploitation of CVE-2026-35663 allows a non-administrative operator to gain full administrative control over the OpenClaw system. The impact of this vulnerability is severe, as it allows unauthorized access to sensitive data, modification of critical system configurations, and the potential for complete system compromise. The vulnerability affects all OpenClaw deployments running versions prior to 2026.3.25. If the OpenClaw system manages sensitive data or controls critical infrastructure, the impact could be devastating.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.25 or later to patch CVE-2026-35663.
*   Implement input validation on the backend to ensure that scope requests are properly authorized based on the user's existing privileges.
*   Monitor application logs for suspicious scope requests during backend reconnects to detect potential exploitation attempts. Enable process creation logging to activate related rules.
*   Deploy the Sigma rule `DetectOpenClawPrivilegeEscalation` to your SIEM and tune for your environment.
