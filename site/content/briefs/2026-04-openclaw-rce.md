---
title: OpenClaw Gateway RCE and Privilege Escalation via Device Pairing Approval
slug: 2026-04-openclaw-rce
description: A critical vulnerability in OpenClaw versions prior to 2026.3.22 allows for remote code execution and privilege escalation by permitting an operator.pairing approver to approve device requests with broader operator scopes than authorized, potentially leading to unauthorized administrative access.
date: "2026-03-26T21:46:07Z"
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

OpenClaw versions prior to 2026.3.22 contain a critical vulnerability that allows for remote code execution (RCE) and privilege escalation. Specifically, the `device.pair.approve` function within the OpenClaw gateway does not properly validate the scopes requested during device pairing. This flaw enables an attacker with `operator.pairing` privileges to approve device requests for scopes exceeding their own, potentially escalating their privileges to `operator.admin`. The vulnerability was…
