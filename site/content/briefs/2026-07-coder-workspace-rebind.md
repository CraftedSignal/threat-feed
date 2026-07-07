---
title: Coder's Workspace App Vulnerability Allows Cross-Workspace Agent Rebinding
slug: 2026-07-coder-workspace-rebind
description: A critical authorization bypass vulnerability (CVE-2026-55429) exists in Coder's workspace application, allowing an attacker with template authorship or external provisioner access to rebind a victim's workspace app to their own agent, enabling them to proxy and compromise the victim's IDE and terminal sessions.
date: "2026-07-06T21:05:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
  - coder
  - application
vendors:
  - Coder
products:
  - 'Coder (vulnerable: >= 2.34.0, < 2.34.2)'
  - 'Coder (vulnerable: >= 2.33.0, < 2.33.8)'
  - 'Coder (vulnerable: >= 2.30.0, < 2.32.7)'
  - 'Coder (vulnerable: < 2.29.17)'
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A user with template authorship or external provisioner access can submit a `CompleteJob` payload... the victim's app row is rebound to the attacker's agent so later app traffic such as IDE and terminal sessions is proxied to the attacker's workspace.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Account Manipulation
    evidence: the victim's app row is rebound to the attacker's agent so later app traffic such as IDE and terminal sessions is proxied to the attacker's workspace.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: later app traffic such as IDE and terminal sessions is proxied to the attacker's workspace.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: later app traffic such as IDE and terminal sessions is proxied to the attacker's workspace.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-9rjw-3gwp-f59v
  - CVE-2026-55429
---

A critical authorization bypass vulnerability, identified as CVE-2026-55429, has been discovered in Coder's workspace application versions prior to v2.34.2, v2.33.8, v2.32.7, and v2.29.17. The flaw resides in the `UpsertWorkspaceApp` and `insertAgentApp` functions, which fail to properly verify ownership of an app ID during the `CompleteJob` payload processing. This allows an attacker with pre-existing elevated access, specifically as a template author or external provisioner operator, to rebind a victim's workspace application to their own malicious agent. First disclosed by Anthropic's Security Team, this vulnerability enables attackers to intercept and proxy a victim's IDE and terminal sessions, leading to unauthorized access, data exposure, and potential compromise of development environments. Defenders must prioritize upgrading their Coder instances to the patched versions immediately to mitigate this severe risk.

## Attack Chain

1.  **Attacker gains elevated access:** The attacker acquires "template authorship" or "external provisioner operator" privileges within the Coder environment, which is a prerequisite for exploitation.
2.  **Victim app ID discovery:** The attacker uses the Coder public API to identify and obtain the unique UUID of a target victim's workspace application.
3.  **Attacker creates malicious agent:** The attacker sets up their own workspace and agent, which will be used to intercept the victim's traffic.
4.  **Craft `CompleteJob` payload:** The attacker constructs a `CompleteJob` payload containing the victim's discovered app UUID and their own malicious agent ID.
5.  **Submit payload:** The attacker submits the crafted `CompleteJob` payload to the Coder system, leveraging their elevated provisioner permissions.
6.  **Cross-workspace agent rebinding:** The `UpsertWorkspaceApp` function, vulnerable to the ID conflict, overwrites the `agent_id` associated with the victim's app UUID, reassigning it to the attacker's agent ID.
7.  **Traffic interception:** Subsequent network traffic, including IDE and terminal sessions initiated by the victim for their workspace application, is transparently proxied to the attacker's workspace and agent.
8.  **Session compromise:** The attacker can now monitor, control, and potentially exfiltrate data from the victim's development environment sessions, leading to unauthorized access and data compromise.

## Impact

Successful exploitation of CVE-2026-55429 allows an attacker with pre-existing elevated permissions to effectively hijack a victim's Coder workspace sessions. This means all activity within the victim's IDE and terminal, including sensitive data, code, credentials, and commands, can be monitored and manipulated by the attacker. This privilege escalation enables unauthorized access to intellectual property, potential insertion of malicious code, and broader compromise of development pipelines, affecting all users of vulnerable Coder instances across various sectors utilizing the platform for development environments.

## Recommendation

*   Prioritize patching all Coder instances to versions v2.34.2, v2.33.8, v2.32.7, or v2.29.17 to remediate CVE-2026-55429.
*   Regularly review and limit permissions for "template author" and "external provisioner operator" roles to only essential personnel to reduce the attack surface for CVE-2026-55429.
