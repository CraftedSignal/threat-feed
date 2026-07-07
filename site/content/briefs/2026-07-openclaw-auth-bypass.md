---
title: OpenClaw Authorization Bypass Vulnerability (<= 2026.5.5)
slug: 2026-07-openclaw-auth-bypass
description: A vulnerability in OpenClaw versions prior to 2026.5.5 allows an unauthorized sender to bypass configured owner-only command policies, enabling the execution of 'owner-style' native commands by senders who should not have such access, potentially leading to unauthorized command execution or privilege escalation.
date: "2026-07-03T11:54:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - authorization-bypass
  - privilege-escalation
  - openclaw
  - npm
vendors:
  - OpenClaw
products:
  - OpenClaw (< 2026.5.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: a sender able to trigger native command handling could authorize a native command without enforcing the configured owner-only command policy.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This could run an owner-style command from a sender that should not have that command access.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-p73f-w79w-jqr5
---

A critical authorization bypass vulnerability, impacting OpenClaw versions up to and including 2026.5.5, has been disclosed. This flaw allows a sender, who is able to trigger the native command handling mechanism within an OpenClaw Gateway, to bypass the configured owner-only command enforcement policy. This means that commands typically restricted to authorized owners can be executed by unauthorized entities. The vulnerability is significant because it can lead to unauthorized command execution or privilege escalation if the affected feature is enabled and reachable by lower-trust input. It is important to note that this advisory specifically targets a flaw in native command authorization and does not imply a general compromise of OpenClaw's trusted-operator model, which assumes that authenticated Gateway operators and installed plugins remain trusted. The first stable patched version addressing this issue is 2026.5.6.

## Attack Chain

1.  An attacker identifies an OpenClaw Gateway instance running a vulnerable version (<= 2026.5.5) where the native command handling feature is enabled and reachable.
2.  The attacker crafts a malicious request or command designed to interact with the OpenClaw Gateway's native command handling interface.
3.  This crafted input is sent to the vulnerable OpenClaw Gateway, triggering the system's native command processing logic.
4.  Due to the flaw in the authorization mechanism, the Gateway fails to correctly enforce the configured owner-only command policy for the incoming native command.
5.  The native command, which requires owner-level privileges, is then executed by the OpenClaw Gateway as if it originated from an authorized owner.
6.  The successful execution of the unauthorized native command leads to the attacker achieving their objective, which could range from unauthorized data modification, system configuration changes, to potentially arbitrary code execution or further privilege escalation within the compromised environment.

## Impact

When the affected native command handling feature is enabled and accessible, this vulnerability allows unauthorized entities to execute commands that should be restricted to owner-level access. The practical impact is highly dependent on the specific configuration of the OpenClaw Gateway and the type of sensitive commands an attacker might be able to trigger. Consequences can include unauthorized data access, modification, or deletion, system configuration changes, and potentially arbitrary code execution with the privileges of the OpenClaw process. While specific victim counts are not available, organizations using affected OpenClaw versions should consider their environments at risk if the vulnerable component is exposed to untrusted input.

## Recommendation

*   Upgrade OpenClaw instances to version `2026.5.6` or higher immediately to patch the vulnerability.
*   As per the brief's mitigation advice, keep native command surfaces limited to trusted senders until patching is complete.
*   Review and narrow channel and tool allowlists for your OpenClaw Gateway to minimize potential exposure.
*   Disable the affected native command handling feature when it is not strictly needed to reduce the attack surface.
