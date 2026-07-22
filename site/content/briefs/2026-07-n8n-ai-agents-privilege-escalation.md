---
title: n8n AI Agents Privilege Escalation via run_node_tool
slug: 2026-07-n8n-ai-agents-privilege-escalation
description: A privilege escalation vulnerability (CVE-2026-65015) exists in n8n's AI Agents feature, allowing users with the read-only Project Viewer role to execute arbitrary tool nodes and access unauthorized credential secrets, potentially leading to arbitrary command execution on the n8n host.
date: "2026-07-22T18:05:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - n8n
  - privilege-escalation
  - vulnerability
  - ai-agents
  - web-application
vendors:
  - n8n GmbH
products:
  - n8n (All versions prior to 2.29.8)
  - n8n (Version 2.30.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: a user with the read-only Project Viewer role could escalate their privileges by chatting with an agent that has node tools enabled. The agent's node-execution tool was authorized only by the `agent:execute` scope and ran nodes using the project's credentials, without verifying that the requesting user was permitted to execute nodes or to access those credentials.
    confidence_band: high
cves:
  - id: CVE-2026-65015
references:
  - https://github.com/advisories/GHSA-x5vx-c2c8-m3w9
rules:
  - title: Detects CVE-2026-65015 Exploitation - Suspicious Shell Spawned by n8n Host Process
    description: Detects potential exploitation of CVE-2026-65015 where the n8n process or its immediate child (node.js) spawns a suspicious shell or command interpreter on a Linux host, indicating arbitrary command execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A high-severity privilege escalation vulnerability, tracked as CVE-2026-65015, has been identified in n8n's AI Agents feature. This flaw allows an authenticated user with a read-only Project Viewer role to bypass intended access controls and execute arbitrary tool nodes, thereby gaining access to credential secrets they are not authorized to view. The vulnerability stems from the `node-execution` tool within the AI Agent, which fails to properly verify user permissions when executing nodes or accessing project credentials, relying only on the broad `agent:execute` scope. This issue impacts organizations using the AI Agents feature and sharing team projects with lower-privileged members, significantly increasing the risk of unauthorized data access and, in configurations with command-capable nodes, potential arbitrary command execution on the underlying n8n host system. Patches have been released in versions 2.29.8 and 2.30.1.

## Attack Chain

1. An attacker, authenticated as a Project Viewer, gains access to an n8n team project that has an AI Agent configured with 'node tools' enabled.
2. The attacker interacts with the AI Agent through the chat interface, crafting an input that specifically triggers the `run_node_tool` function.
3. The AI Agent's `node-execution` tool receives the request to execute a node, initiated by the Project Viewer.
4. The `node-execution` tool proceeds to execute the requested node using the project's configured credentials.
5. Crucially, the `node-execution` tool's authorization mechanism relies solely on the `agent:execute` scope and fails to verify that the requesting Project Viewer has the necessary permissions to execute nodes or access the specific credentials involved.
6. This bypass allows the Project Viewer to execute arbitrary tool nodes beyond their assigned read-only privileges, effectively escalating their capabilities within the n8n environment.
7. The Project Viewer can now access and utilize sensitive credential secrets stored within the project, which they were previously unauthorized to read, facilitating further internal reconnaissance or lateral movement.
8. If the n8n instance has command- or file-capable tool nodes (such as 'Execute Command' or 'SSH') enabled, the Project Viewer can leverage this escalated privilege to achieve arbitrary command execution on the n8n host system, leading to full system compromise.

## Impact

The vulnerability (CVE-2026-65015) in n8n's AI Agents feature allows a read-only Project Viewer to escalate their privileges within the n8n environment. This leads to unauthorized execution of arbitrary tool nodes and access to sensitive credential secrets, enabling the attacker to perform actions explicitly denied by their role. For instances where command- or file-capable tool nodes (e.g., 'Execute Command', 'SSH') are enabled, this privilege escalation can be leveraged for arbitrary command execution on the n8n host. This directly impacts organizations using n8n with AI Agents and team projects, risking data exfiltration, system compromise, and unauthorized manipulation of workflows by lower-privileged users. All users of the AI Agents feature who share team projects are potentially affected.

## Recommendation

* Upgrade n8n instances immediately to version 2.29.8 or 2.30.1, or later, to remediate CVE-2026-65015.
* If immediate upgrade is not possible, consider disabling the AI Agents module by removing `agents` from the `N8N_ENABLED_MODULES` environment variable as a temporary mitigation for CVE-2026-65015.
* Restrict project membership to fully trusted users only and avoid granting Project Viewer access to untrusted users on projects containing agents with node tools enabled.
* Disable command-execution nodes (e.g., `Execute Command`, `SSH`) within n8n workflows if they have been re-enabled, to limit the potential impact of arbitrary command execution from successful exploitation.
* Deploy the Sigma rule in this brief to your SIEM to detect suspicious process creation activities that may indicate successful arbitrary command execution on Linux hosts.
