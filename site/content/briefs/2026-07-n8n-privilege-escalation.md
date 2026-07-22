---
title: AI Agents Project Viewer Privilege Escalation in n8n
slug: 2026-07-n8n-privilege-escalation
description: A privilege escalation vulnerability exists in n8n's AI Agents feature, specifically within the node-execution tool, due to a lack of proper authorization checks, allowing a Project Viewer user to escalate their privileges by interacting with an agent configured with enabled node tools, thereby executing arbitrary nodes and gaining unauthorized access to credential secrets in n8n versions prior to 2.30.1.
date: "2026-07-22T17:57:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - n8n
vendors:
  - n8n
products:
  - n8n (< 2.30.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A Project Viewer user can escalate privileges by chatting with an agent that has node tools enabled, executing arbitrary nodes and accessing credential secrets without proper authorization verification.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w46p-w7w2-fr9g
---

A high-severity privilege escalation vulnerability (GHSA-w46p-w7w2-fr9g) has been identified in n8n, an open-source workflow automation platform, specifically affecting versions prior to 2.30.1. This flaw resides within the AI Agents feature's `run_node_tool` where authorization checks are insufficient. An authenticated Project Viewer user can exploit this weakness by engaging with an AI agent that has node tools enabled. This interaction allows the viewer to execute arbitrary nodes and gain unauthorized access to sensitive credential secrets, effectively escalating their privileges beyond their intended scope. The vulnerability can lead to critical data exposure and system compromise if not addressed promptly.

## Attack Chain

1. A Project Viewer user, who already possesses legitimate but limited access to an n8n project, identifies an AI agent configured within the environment.
2. The AI agent in question has "node tools" functionality enabled, allowing it to execute n8n nodes based on user input.
3. The Project Viewer user interacts with this AI agent via the chat interface, crafting malicious input or queries.
4. The AI agent, due to the lack of proper authorization checks in its `run_node_tool` component, processes the viewer's input as legitimate.
5. The AI agent then executes arbitrary n8n nodes as specified by the Project Viewer user.
6. Through these arbitrarily executed nodes, the Project Viewer user gains unauthorized access to credential secrets or other sensitive data that should only be accessible to higher-privileged users.
7. This unauthorized access to sensitive resources constitutes a privilege escalation, allowing the Project Viewer to perform actions beyond their assigned role.

## Impact

The successful exploitation of this vulnerability leads to privilege escalation within the n8n platform. A Project Viewer user, typically restricted from accessing sensitive configurations, can gain unauthorized access to credential secrets. This exposure of credentials could lead to broader system compromise, unauthorized access to integrated services, or data exfiltration from connected applications. While the advisory does not specify the number of victims or targeted sectors, any organization using affected n8n versions with the AI Agents feature enabled is at risk of sensitive data exposure and potential breaches.

## Recommendation

* Update n8n to version 2.30.1 or later immediately to patch the GHSA-w46p-w7w2-fr9g vulnerability.
* Review the configuration of AI Agents in n8n, ensuring that node tools are only enabled when strictly necessary and with appropriate access controls.
