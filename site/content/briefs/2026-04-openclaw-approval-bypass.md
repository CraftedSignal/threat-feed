---
title: OpenClaw StrictInlineEval Approval Bypass Vulnerability (CVE-2026-42423)
slug: 2026-04-openclaw-approval-bypass
description: OpenClaw before 2026.4.8 contains an approval-timeout fallback mechanism that allows attackers to bypass strictInlineEval explicit-approval requirements on gateway and node exec hosts, leading to arbitrary command execution.
date: "2026-04-29T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
  - execution
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1205
    technique_name: Traffic Signaling
cves:
  - id: CVE-2026-42423
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42423
  - https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-q2gc-xjqw-qp89
  - https://www.vulncheck.com/advisories/openclaw-strictinlineeval-approval-boundary-bypass-via-approval-timeout-fallback
rules:
  - title: Potential OpenClaw InlineEval Bypass Attempt
    description: Detects potential attempts to bypass strictInlineEval approval mechanism in OpenClaw by monitoring for eval commands executed shortly after an approval timeout.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1205
    data_sources:
      - application
      - openclaw
  - title: OpenClaw Unapproved InlineEval Command Execution
    description: Detects inline eval commands being executed in OpenClaw without prior explicit user approval, potentially indicating exploitation of CVE-2026-42423.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1205
    data_sources:
      - application
      - openclaw
rules_count: 2
---

OpenClaw, a software application, is vulnerable to an approval-timeout bypass (CVE-2026-42423) affecting versions prior to 2026.4.8. This vulnerability stems from a flaw in the strictInlineEval approval mechanism, where an approval-timeout fallback allows the execution of inline eval commands without explicit user approval. An attacker with low privileges can exploit this vulnerability on gateway and node exec hosts to circumvent the intended security boundary. This can lead to unauthorized command execution and potential system compromise. Defenders should upgrade to version 2026.4.8 or implement mitigations to prevent exploitation.

## Attack Chain

1.  Attacker gains low-privilege access to a gateway or node exec host running a vulnerable version of OpenClaw (prior to 2026.4.8).
2.  The attacker crafts a malicious inline eval command intended to be executed on the system.
3.  The attacker attempts to execute the malicious inline eval command, triggering the strictInlineEval approval mechanism.
4.  The system initiates the explicit approval process, awaiting user confirmation before executing the command.
5.  The attacker waits for the pre-configured approval-timeout to expire without providing any explicit approval.
6.  The approval-timeout fallback mechanism is triggered due to the lack of user approval within the defined timeframe.
7.  The system bypasses the explicit-approval requirement due to the timeout fallback, and the malicious inline eval command is executed.
8.  The attacker achieves arbitrary command execution on the affected host, potentially escalating privileges and compromising the system.

## Impact

Successful exploitation of CVE-2026-42423 allows an attacker to bypass intended security boundaries and execute arbitrary commands on OpenClaw gateway and node exec hosts. This can lead to privilege escalation, unauthorized data access, and potential system compromise. The severity is rated as high (CVSS 7.5) due to the potential for significant impact on confidentiality, integrity, and availability. The number of affected systems depends on the deployment scope of vulnerable OpenClaw versions.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.8 or later to patch CVE-2026-42423.
*   Monitor OpenClaw logs for indicators of unauthorized inline eval command execution, focusing on unexpected activity following approval timeouts.
*   Implement network segmentation to limit the blast radius of potential compromises, should an attacker successfully exploit CVE-2026-42423 and gain unauthorized access.
