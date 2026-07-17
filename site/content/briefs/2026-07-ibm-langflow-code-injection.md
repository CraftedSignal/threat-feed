---
title: IBM Langflow OSS Code Injection Vulnerability in ToolGuard (CVE-2026-9135)
slug: 2026-07-ibm-langflow-code-injection
description: An authenticated attacker can exploit CVE-2026-9135, a code injection vulnerability in IBM Langflow OSS versions 1.0.0 through 1.9.2, to bypass security controls and achieve arbitrary Python code execution on the backend through unvalidated dynamic CodeInput fields in the ToolGuard integration, potentially escalating privileges via cross-tenant flow manipulation.
date: "2026-07-17T19:19:49Z"
lastmod: "2026-07-17T21:19:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code-injection
  - vulnerability
  - rce
  - langflow
  - hard-coded-credentials
  - ibm
vendors:
  - IBM
products:
  - Langflow OSS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This allows authenticated users with flow creation privileges to achieve arbitrary Python code execution on the backend
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability can be escalated through cross-tenant flow manipulation via the agentic MCP update_flow_component_field tool, which accepts attacker-controlled user_id parameters, enabling attackers to inject malicious code into victim users' flows.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: IBM Langflow OSS 1.0.0 through 1.10.1 contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.
    confidence_band: high
cves:
  - id: CVE-2026-9135
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9135
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13446
  - https://www.ibm.com/support/pages/node/7279991
updates:
  - at: "2026-07-17T21:19:13Z"
    level: L2
    summary: 'merged source coverage: IBM Langflow OSS Hard-coded Credentials Vulnerability CVE-2026-13446'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-13446
---

CVE-2026-9135 describes a critical code injection vulnerability affecting IBM Langflow OSS versions 1.0.0 through 1.10.0, specifically impacting Langflow versions up to 1.9.2 (commit 94981c443d4918517b9e8163d70fc598dc33a32d). This flaw resides in the Policies component's ToolGuard integration, allowing authenticated users with flow creation privileges to bypass the `allow_custom_components=false` security control. The vulnerability stems from an insufficient validation mechanism that only scrutinizes the main component source code (`node_template["code"]["value"]`) while failing to validate dynamic `CodeInput` fields, which are used to store generated ToolGuard Python files. Attackers can embed malicious Python code within these unvalidated dynamic fields, which is then persisted in `Flow.data` and executed server-side when a guarded tool is invoked via the ToolGuard runtime. This enables arbitrary Python code execution on the backend and can be escalated through cross-tenant flow manipulation using the `update_flow_component_field` tool, potentially affecting other users' flows. Under specific misconfigurations (`AUTO_LOGIN=true`, `NEW_USER_IS_ACTIVE=true`), authentication requirements for the attack can be significantly reduced.

## Attack Chain

1. An authenticated attacker obtains flow creation privileges within IBM Langflow OSS.
2. The attacker crafts malicious Python code designed for arbitrary execution on the backend.
3. The attacker embeds this malicious Python code into dynamic `CodeInput` fields of a Langflow component.
4. The Langflow Policies component's ToolGuard integration performs an insufficient validation check, only examining the main component source code and bypassing the `allow_custom_components=false` control.
5. The malicious code embedded in the unvalidated dynamic fields is persisted within `Flow.data` when the flow is saved.
6. When a guarded tool within the manipulated flow is subsequently invoked, the ToolGuard runtime executes the malicious Python code server-side.
7. The attacker can further escalate by utilizing the `agentic MCP update_flow_component_field` tool with attacker-controlled `user_id` parameters to inject malicious code into other victim users' flows, achieving cross-tenant manipulation.
8. In environments configured with `AUTO_LOGIN=true` and `NEW_USER_IS_ACTIVE=true`, the initial authentication requirements for the attacker may be reduced, broadening the attack surface.

## Impact

Successful exploitation of CVE-2026-9135 grants authenticated attackers arbitrary Python code execution on the backend systems running IBM Langflow OSS. This can lead to full compromise of the underlying server, data exfiltration, or further lateral movement within the network. The vulnerability's ability to facilitate cross-tenant flow manipulation through the `update_flow_component_field` tool means that an attacker could inject malicious code into other users' environments, impacting data integrity and confidentiality across the platform. Furthermore, specific misconfigurations can lower authentication barriers, potentially increasing the number of vulnerable instances and the ease of exploitation.

## Recommendation

* Immediately update IBM Langflow OSS to a patched version beyond 1.9.2 or apply the provided security patch for CVE-2026-9135.
* Review and ensure that the `AUTO_LOGIN` and `NEW_USER_IS_ACTIVE` configurations are set appropriately for your environment to prevent reduced authentication requirements that could facilitate exploitation of CVE-2026-9135.
* Monitor server-side logs on systems running IBM Langflow OSS for unusual process creations or outbound network connections from the Langflow application process, which could indicate arbitrary Python code execution.
