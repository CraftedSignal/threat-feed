---
title: OpenClaw Gateway RCE and Privilege Escalation via Device Pairing Approval
slug: 2026-04-openclaw-rce
description: A critical vulnerability in OpenClaw versions prior to 2026.3.22 allows for remote code execution and privilege escalation by permitting an operator.pairing approver to approve device requests with broader operator scopes than authorized, potentially leading to unauthorized administrative access.
date: "2026-03-26T21:46:07Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - openclaw
  - rce
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-hf68-49fm-59cq
rules:
  - title: Detect Suspicious Device Pairing Approval
    description: Detects attempts to approve device pairing requests with escalated privileges by monitoring for device pairing events where the requested scope exceeds the approver's scope.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - application
      - openclaw
  - title: Detect Admin Activity from Newly Paired Device
    description: Detects unusual administrative activity originating from devices that were recently paired, potentially indicating exploitation of the privilege escalation vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - application
      - openclaw
rules_count: 2
---

OpenClaw versions prior to 2026.3.22 contain a critical vulnerability that allows for remote code execution (RCE) and privilege escalation. Specifically, the `device.pair.approve` function within the OpenClaw gateway does not properly validate the scopes requested during device pairing. This flaw enables an attacker with `operator.pairing` privileges to approve device requests for scopes exceeding their own, potentially escalating their privileges to `operator.admin`. The vulnerability was reported by @zpbrent and patched in version 2026.3.22, with the fix present in subsequent releases (v2026.3.23 and v2026.3.23-2). Defenders should upgrade vulnerable instances immediately. The affected package is npm/openclaw.

## Attack Chain

1. An attacker gains initial access with `operator.pairing` privileges.
2. The attacker initiates a device pairing request, specifying a broader scope such as `operator.admin`.
3. The vulnerable `device.pair.approve` function, lacking proper scope validation, approves the device pairing request.
4. The newly paired device now possesses the elevated `operator.admin` privileges.
5. The attacker leverages the escalated privileges to execute administrative functions, potentially including modifying system configurations or accessing sensitive data.
6. The attacker deploys malicious code or alters existing code through the compromised administrative access.
7. The system executes the attacker's malicious code, leading to remote code execution.
8. The attacker maintains persistent access and control over the OpenClaw gateway.

## Impact

Successful exploitation of this vulnerability allows attackers to escalate privileges from `operator.pairing` to `operator.admin` on OpenClaw gateways. This privilege escalation can lead to unauthorized access to sensitive data, modification of system configurations, and remote code execution, potentially compromising the entire OpenClaw environment. Given the critical nature of gateways in controlling access and data flow, this vulnerability could result in significant data breaches and system downtime. The impact is especially severe in environments where OpenClaw manages critical infrastructure or sensitive data.

## Recommendation

*   Upgrade all OpenClaw installations to version 2026.3.22 or later to patch the vulnerability (reference: Affected Packages / Versions).
*   Deploy the Sigma rule `Detect Suspicious Device Pairing Approval` to monitor for unauthorized scope escalation attempts (reference: rules).
*   Review and audit existing device pairing configurations to identify any instances where devices may have been granted excessive privileges due to this vulnerability.
*   Monitor gateway logs for unusual administrative activity originating from recently paired devices (reference: Sigma rule `Detect Admin Activity from Newly Paired Device`).
