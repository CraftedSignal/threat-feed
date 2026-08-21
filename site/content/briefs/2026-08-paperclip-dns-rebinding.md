---
title: Remote Code Execution in Paperclip via DNS Rebinding
slug: 2026-08-paperclip-dns-rebinding
description: Paperclip versions prior to 0.3.1 are vulnerable to remote code execution due to improper Host header validation when running in 'local_trusted' mode, allowing attackers to leverage DNS rebinding to execute arbitrary commands.
date: "2026-08-21T15:25:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - dns-rebinding
  - developer-tools
  - web-vulnerability
vendors:
  - paperclipai
products:
  - Paperclip (< 0.3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An attacker can craft a malicious webpage that, when visited by a developer running Paperclip locally, uses DNS rebinding to make authenticated API requests.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: execute arbitrary commands through the process adapter.
    confidence_band: high
cves:
  - id: CVE-2026-77087
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77087
  - https://github.com/paperclipai/paperclip/security/advisories/GHSA-x8hx-rhr2-9rf7
  - https://www.vulncheck.com/advisories/paperclip-before-remote-code-execution-via-dns-rebinding
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Development Teams
  immediate_actions:
    - action: Patch Paperclip to 0.3.1 or higher
      owner: Development Teams
      due: 24h
      evidence: CVE-2026-77087 remediation
  mitigation_plan:
    - priority: immediate
      action: Disable 'local_trusted' mode in Paperclip config if immediate patching is not possible
      owner: Development Teams
      addresses: CVE-2026-77087
      evidence: Source advisory notes 'local_trusted' mode failure as root cause
---

Paperclip versions before 0.3.1 contain a critical security vulnerability (CVE-2026-77087) affecting users who run the software in its default 'local_trusted' mode. The vulnerability stems from a failure to validate the Host header during incoming API requests. An attacker can exploit this via DNS rebinding; by tricking a developer into visiting a malicious webpage, the attacker can force the victim's browser to make unauthorized, authenticated API requests to the locally running Paperclip instance. These requests interact with the process adapter, ultimately resulting in remote code execution on the developer's machine. This is a significant risk for development environments where Paperclip is configured to trust local traffic without strict origin verification.

## Attack Chain

1. The attacker hosts a malicious website configured to perform DNS rebinding against a target domain that resolves to 127.0.0.1.
2. A developer or user running Paperclip locally navigates to the malicious website in their browser.
3. The website's scripts initiate a DNS rebinding attack, causing the browser to resolve the attacker-controlled domain to a local address (e.g., localhost).
4. The browser sends a cross-origin HTTP request to the Paperclip API running on the local host.
5. The Paperclip application, running in 'local_trusted' mode, fails to perform Host header validation and accepts the forged request.
6. The request triggers the Paperclip process adapter, which interprets the API command as a legitimate instruction.
7. The process adapter executes the attacker-supplied command on the developer's local operating system with the privileges of the Paperclip process.

## Impact

Successful exploitation allows an unauthenticated, remote attacker to execute arbitrary commands on a developer's workstation. This can lead to full system compromise, source code theft, credential exfiltration, and lateral movement into the developer's internal network. Given the CVSS score of 9.6, this vulnerability poses a severe threat to organizations using the affected versions of Paperclip in development environments.

## Recommendation

Prioritized actions for security teams:
- Update the Paperclip package to version 0.3.1 or higher across all development environments immediately to address CVE-2026-77087.
- Audit development workstations to identify any active instances of Paperclip running in 'local_trusted' mode.
- Implement browser-based protections or host-level firewall rules to prevent cross-origin requests from reaching local services on development machines.
- Review documentation for Paperclip configurations to ensure that 'local_trusted' mode is restricted to secure network segments if it cannot be disabled.
