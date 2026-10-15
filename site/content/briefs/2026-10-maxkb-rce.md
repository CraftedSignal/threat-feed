---
title: Remote Command Execution in MaxKB via Prompt Injection
slug: 2026-10-maxkb-rce
description: MaxKB AI assistant platform is vulnerable to unauthenticated remote command execution due to prompt injection flaws in the 'execute' tool and insufficient sandbox escaping protections.
date: "2026-10-15T13:00:33Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - InertFluid
cpes:
  - cpe:2.3:a:1panel_dev:maxkb:*:*:*:*:*:*:*:*
vendors:
  - 1Panel-dev
products:
  - MaxKB (<= 2.10.5-lts)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Prompt injection in MaxKB with tools leads to command execution as root.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The AI assistant features an execute tool that lacks a human-in-the-loop approval gate.
    confidence_band: high
cves:
  - id: CVE-2026-77521
    cvss: 10
    epss: 0.01049
references:
  - https://sploitus.com/exploit?id=70242680-9D9B-518C-B50D-D493F2072223
  - https://github.com/1Panel-dev/MaxKB/security/advisories/GHSA-f36j-f34j-h3rx
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Implement manual approval gate for 'execute' tool
      owner: IT Operations
      due: 24h
      evidence: Advisory confirms absence of human-in-the-loop gate is core to CVSS 10.0 rating
    - action: Upgrade MaxKB to version 2.10.5-lts
      owner: IT Operations
      due: 48h
      evidence: Vendor patch fixes sandbox escape vulnerability
  mitigation_plan:
    - priority: immediate
      action: Enforce principle of least privilege by running MaxKB service as a non-root user
      owner: IT Operations
      addresses: CVE-2026-77521
      evidence: PoC demonstrates code execution occurs as root
---

MaxKB, an open-source enterprise AI assistant and RAG platform, contains a critical vulnerability (CVE-2026-77521) that permits remote command execution (RCE). The vulnerability stems from two primary architectural flaws: a missing human-in-the-loop approval gate for the AI's internal 'execute' tool and a flawed sandbox mechanism that fails to sanitize shell metacharacters. 

An attacker can leverage prompt injection - either through direct user interaction with the AI assistant or by poisoning ingested knowledge base (KB) documents - to trick the model into invoking the 'execute' shell tool. Because the 'execute' tool is not gated, the model performs this action without operator authorization. Furthermore, the application's sandbox implementation was previously susceptible to shell metacharacter escapes, allowing injected payloads to break out of the intended execution environment and run commands with root privileges. While version 2.10.5-lts provides hardening against the sandbox escape, the underlying lack of an authorization gate for the 'execute' tool remains, leaving systems vulnerable to unauthorized command execution if the assistant is prompted to use the tool.

## Attack Chain

1. Attacker identifies a target instance of MaxKB running a version affected by CVE-2026-77521.
2. Attacker prepares a malicious document or direct chat prompt containing an adversarial prompt injection payload.
3. Target instance ingests the malicious document into its knowledge base or receives the chat message.
4. The AI assistant processes the input and triggers the internal 'execute' tool, which lacks a human-approval requirement.
5. The injected command, containing shell metacharacters (e.g., ';'), is passed to the application backend.
6. The `SandboxShellBackend` executes the command string, failing to neutralize the metacharacters.
7. The system executes the injected payload as root, granting the attacker control over the host environment.

## Impact

The vulnerability is rated CVSS 10.0 and allows an unauthenticated attacker to achieve full root-level remote command execution. Successful exploitation results in complete compromise of the MaxKB application server, potentially leading to unauthorized data exfiltration, lateral movement within the network, and the disruption of AI services.

## Recommendation

* Immediate priority: Manually gate the 'execute' tool within the MaxKB agency configuration to require human approval before any shell command is executed, as the current vendor patch does not address this logic flaw.
* Update all MaxKB deployments to at least version 2.10.5-lts to mitigate the documented sandbox escape path.
* Implement strict validation on all ingested documents and user-provided inputs to detect and block common prompt injection patterns before they reach the AI agent.
* Restrict the privileges of the system user running the MaxKB service to ensure it does not run as root, thereby limiting the potential damage of a successful command injection.
