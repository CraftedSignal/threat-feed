---
title: OpenClaw Execution Approval Bypass Vulnerability (CVE-2026-41380)
slug: 2026-04-openclaw-exec-approval-bypass
description: OpenClaw before 2026.3.28 contains an execution approval vulnerability in exec-approvals-allowlist.ts that allows attackers to bypass intended execution restrictions by exploiting trust relationships with wrapper carrier executables, leading to privilege escalation and defense evasion.
date: "2026-04-29T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-41380
  - execution-approval-bypass
  - privilege-escalation
  - defense-evasion
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Execution Guardrails
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
cves:
  - id: CVE-2026-41380
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41380
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-p4x4-2r7f-wjxg
  - https://www.vulncheck.com/advisories/openclaw-arbitrary-execution-allowlist-via-wrapper-carrier-executables
rules:
  - title: Detect Suspicious OpenClaw Wrapper Execution
    description: Detects suspicious execution of wrapper executables potentially exploiting CVE-2026-41380 to bypass execution approvals.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect OpenClaw Exec-Approvals-Allowlist.ts Modification
    description: Detects modification of exec-approvals-allowlist.ts, potentially indicating an attempt to weaken execution approval boundaries.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

OpenClaw, a software of undetermined function, is vulnerable to an execution approval bypass (CVE-2026-41380) affecting versions prior to 2026.3.28. The vulnerability resides in `exec-approvals-allowlist.ts`, where the system incorrectly trusts wrapper carrier executables instead of the actual invoked targets. This flaw allows attackers to manipulate positional carrier executable routing through dispatch wrappers. By exploiting this, attackers can establish overly broad allowlist entries, effectively weakening the intended execution approval boundaries. This vulnerability was reported on April 28, 2026, and poses a significant risk by allowing unauthorized code execution.

## Attack Chain

1.  Attacker gains initial access to a system with OpenClaw installed, potentially through social engineering or exploiting other vulnerabilities.
2.  The attacker identifies a dispatch wrapper executable that is already on the allowlist.
3.  The attacker crafts a malicious payload to be executed through the identified wrapper.
4.  The attacker leverages positional carrier executable routing to pass the malicious payload to the wrapper.
5.  OpenClaw's `exec-approvals-allowlist.ts` incorrectly trusts the wrapper, adding it to the allow-always list.
6.  The attacker executes arbitrary commands using the allowlisted wrapper with the malicious payload, bypassing intended restrictions.
7.  The attacker escalates privileges by executing privileged commands through the bypassed execution approval mechanism.
8.  The attacker achieves persistence by utilizing the now-trusted wrapper to execute malicious code repeatedly.

## Impact

Successful exploitation of CVE-2026-41380 allows attackers to bypass intended execution restrictions within OpenClaw. This can lead to arbitrary code execution, privilege escalation, and persistent malicious activity. The vulnerability allows attackers to effectively weaken the security posture of systems relying on OpenClaw's execution approval mechanisms, potentially leading to complete system compromise. The precise number of affected installations is unknown, but any system running a vulnerable version of OpenClaw is at risk.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.28 or later to remediate CVE-2026-41380.
*   Implement the Sigma rule "Detect Suspicious OpenClaw Wrapper Execution" to identify potential exploitation attempts.
*   Review existing allowlist entries within OpenClaw to identify and remove any overly broad or suspicious entries that may have been created through exploitation of CVE-2026-41380.
*   Monitor OpenClaw's logs for unexpected or unauthorized execution events related to wrapper executables as described in the vulnerability details.
