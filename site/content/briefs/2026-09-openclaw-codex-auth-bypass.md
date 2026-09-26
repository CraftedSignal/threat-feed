---
title: Authorization Bypass Vulnerability in OpenClaw Codex
slug: 2026-09-openclaw-codex-auth-bypass
description: OpenClaw Codex versions before 2026.7.1 contain an authorization bypass vulnerability allowing non-owner users to create native conversation bindings and execute arbitrary host-level commands.
date: "2026-09-26T06:57:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openclaw:codex:*:*:*:*:*:*:*:*
vendors:
  - OpenClaw
products:
  - Codex (< 2026.7.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Non-owner channel senders with command access can create bindings to the native Codex runtime.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Execute host-capable turns with access to files, tools, and processes.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The attacker can execute host-capable turns and access files, tools, and processes with the permissions of the Codex runtime.
    confidence_band: high
cves:
  - id: CVE-2026-100586
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100586
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenClaw Codex to version 2026.7.1 or later
      owner: IT Operations
      addresses: CVE-2026-100586
      evidence: Source explicitly identifies vulnerability in versions before 2026.7.1
---

OpenClaw Codex versions prior to 2026.7.1 are susceptible to an authorization bypass vulnerability (CVE-2026-100586) involving the creation of native conversation bindings. The vulnerability stems from a failure to properly validate authorization levels when a user attempts to bind a conversation to the native Codex runtime. An attacker who is a channel participant, even without owner-level privileges, can leverage this flaw to create unauthorized bindings. 

Once a malicious binding is established, the attacker can execute "host-capable" turns. Because these turns are processed by the native Codex runtime, they inherit the privileges of the application process itself. This allows for unauthorized interaction with the host file system, execution of local system tools, and potential manipulation of running processes. Given the severity of the access provided, this vulnerability represents a significant risk to host environment integrity and data confidentiality. Defenders should prioritize patching all instances of OpenClaw Codex to version 2026.7.1 or later.

## Impact

Successful exploitation allows unprivileged channel participants to gain elevated access within the host environment. This can lead to unauthorized exfiltration of sensitive files, execution of malicious system commands, and potential lateral movement or persistence by manipulating system processes. The scope of impact is limited to the system where the affected Codex instance is running.

## Recommendation

* Patch all internet-facing and internal installations of OpenClaw Codex to version 2026.7.1 or later to remediate CVE-2026-100586.
* Audit application logs for abnormal creation of native conversation bindings or execution of unexpected host-level commands originating from non-owner user accounts.
* Enforce strict network segmentation for hosts running the Codex runtime to limit potential post-exploitation activity if the service is compromised.
