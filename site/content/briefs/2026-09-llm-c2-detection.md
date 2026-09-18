---
title: Detection of Malicious Use of LLM Endpoints for Command and Control
slug: 2026-09-llm-c2-detection
description: Detection logic identifying unsigned binaries or scripting utilities establishing network connections to various Large Language Model API endpoints for potential command and control.
date: "2026-09-18T19:04:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - ai-security
  - endpoint-detection
  - c2-traffic
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: Malwares may leverage the capabilities of LLM to perform actions in the affected system in a dynamic way.
    confidence_band: high
rules:
  - title: Connection to Common Large Language Model Endpoints
    description: Detects network connections to known LLM service domains initiated by unsigned binaries or common scripting utilities, a pattern often used by malware for C2.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1102.002
    data_sources:
      - network_connection
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to monitor connections to LLM domains
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 4ae94fc1-f08f-419f-b692-053d28219380
  hunt_leads:
    - lead: Search network logs for connections to documented LLM domains
      technique_id: T1102.002
      data_needed:
        - DNS and Proxy logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source provides list of C2-relevant AI API domains
  mitigation_plan:
    - priority: short_term
      action: Restrict outbound access for scripting tools and unsigned processes
      owner: IT Operations
      addresses: Unauthorized C2 communication
      evidence: Rule note on response and remediation
---

Adversaries are increasingly leveraging the capabilities of Large Language Models (LLMs) to dynamically perform malicious actions on compromised systems. This threat involves malware or post-exploitation scripts that utilize legitimate LLM APIs as a proxy for command and control (C2) or to execute logic within the affected system. This behavior is characterized by network connections to a broad range of AI and ML infrastructure providers, including OpenAI, Anthropic, Mistral, and various specialized inference services, initiated by unsigned binaries or common Windows/macOS scripting utilities such as PowerShell, curl, or WScript. Because these connections mimic legitimate traffic to AI services, detection must focus on the process context, specifically identifying unauthorized or unsigned code initiating the requests.

## Attack Chain

1. Initial access is established through standard means, such as spearphishing or exploiting a public-facing service.
2. The attacker drops an unsigned or obfuscated payload (e.g., PowerShell script or malicious executable) into a non-standard directory like /tmp/ or \Users\Public\.
3. The malicious process executes and gathers system information or target data.
4. The process initiates an HTTPS connection to an LLM provider's API endpoint (e.g., api.openai.com).
5. The attacker sends instructions or prompts to the LLM API to generate code or malicious commands tailored to the system state.
6. The response from the LLM is parsed and executed locally by the malicious process.
7. The process performs further actions, such as exfiltrating data or establishing persistent access, based on the AI-generated logic.

## Impact

Successful exploitation allows attackers to bypass traditional static signature-based defenses by using dynamically generated, AI-assisted malicious logic. This increases the complexity of incident response and attribution, as the malicious commands originate from a legitimate, trusted API service. Affected organizations risk unauthorized data exfiltration, automated system exploitation, and stealthy persistence, as the C2 channel is obscured by traffic destined for reputable AI infrastructure.

## Recommendation

1. Deploy the provided EQL-based detection rules across all endpoints to monitor for suspicious processes communicating with known LLM API domains.
2. Implement strict network segmentation and egress filtering to prevent unauthorized processes from accessing cloud-based AI service APIs.
3. Perform a historical search on network proxy and DNS logs for connections to the listed LLM endpoints originating from high-risk or non-standard process paths.
4. Review and harden systems to prevent the execution of unsigned binaries or unauthorized scripting tools in sensitive environments.
5. If an alert triggers, investigate the process tree and parent process to confirm whether the connection originates from a legitimate user-installed application or a malicious actor.
