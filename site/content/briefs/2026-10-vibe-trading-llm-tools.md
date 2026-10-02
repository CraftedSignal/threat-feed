---
title: Vibe-Trading LLM Tool Exploitation Leading to RCE and SSRF
slug: 2026-10-vibe-trading-llm-tools
description: Multiple unauthenticated RCE and SSRF primitives in Vibe-Trading's LLM-callable tool registry allow remote attackers to achieve root-level code execution and internal network scanning.
date: "2026-10-02T22:49:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - llm-security
  - rce
  - ssrf
  - command-injection
products:
  - Vibe-Trading
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The BashTool and BackgroundRunTool pass LLM-emitted command verbatim to subprocess.run(shell=True) with zero filtering.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: The agent is susceptible to prompt-injection in any document the LLM agent processes.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The backtest runner unconditionally executes top-level statements via exec_module before validation.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-jqmf-mx4f-hfr6
iocs:
  - type: domain
    value: r.jina.ai
ioc_counts:
  domain: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Implement authentication on port 8899 and restrict access to the API.
      owner: SOC
      due: 24h
      evidence: The absence of authentication on /sessions allows any network-adjacent attacker to trigger tool primitives.
  hunt_leads:
    - lead: Search for shell commands initiated by Python processes in container logs.
      technique_id: T1059
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: BashTool and BackgroundRunTool trigger shell execution via subprocess.run(shell=True).
---

Vibe-Trading, a framework for LLM-based trading agents, contains several critical vulnerabilities within its auto-discovered tool registry. These flaws allow an unauthenticated attacker, interacting with the system's exposed API on port 8899, to trigger arbitrary OS command execution or exploit improper module loading logic. The platform provides tools such as 'BashTool' and 'BackgroundRunTool', which pass LLM-supplied commands directly to 'subprocess.run(shell=True)' without filtering, escaping, or access controls. Furthermore, the backtest runner unconditionally executes arbitrary Python code from files staged via the session, and the 'read_url' tool facilitates server-side request forgery (SSRF) by forwarding unsanitized URLs to the Jina Reader API. Because the container runs with root privileges and lacks authentication on its messaging endpoints, these primitives can be chained to compromise the host environment. The agent's propensity to process document-based instructions also enables prompt-injection-based RCE for users who do not initially possess malicious intent.

## Attack Chain

1. Attacker sends a POST request to the unauthenticated /sessions endpoint to initialize a new conversation session.
2. Attacker sends an unauthenticated message to the session containing an LLM prompt that includes a malicious command (e.g., 'id; uname -a').
3. The agent incorrectly interprets the prompt as a legitimate request for the 'BashTool' or 'BackgroundRunTool'.
4. 'BashTool' or 'BackgroundRunTool' receives the malicious string and passes it directly to the system shell via 'subprocess.run(command, shell=True)'.
5. The OS executes the injected commands with root privileges (uid=0) inside the container.
6. Attacker observes command output in the session event stream or through the background task status check.
7. Attacker uses 'WriteFileTool' to stage a malicious 'signal_engine.py' file containing arbitrary Python code.
8. Attacker invokes 'BacktestTool', causing the runner to load the module and execute the attacker's Python code unconditionally.

## Impact

Successful exploitation allows unauthenticated remote attackers to achieve full system compromise (root shell) within the containerized environment. Given the nature of trading platforms, this could lead to theft of API credentials, manipulation of trading logic, or lateral movement into internal infrastructure. The lack of authentication and presence of SSRF capabilities further increase the risk, as the platform can be used as a pivot point for internal network scanning or external data exfiltration.

## Recommendation

- Implement strict authentication and authorization checks on all API endpoints, specifically for session creation and message processing, to prevent unauthenticated access.
- Replace 'shell=True' calls in 'BashTool' and 'BackgroundRunTool' with argument lists (shell=False) and enforce a strict allowlist of permitted commands or parameters.
- Patch the module loading logic in 'agent/backtest/runner.py' to validate the presence of the 'SignalEngine' class or use restricted execution environments before calling 'exec_module'.
- Implement a rigorous URL validation and filtering mechanism (allowlist for domains, blocking of private IP ranges) in 'agent/src/tools/web_reader_tool.py' to mitigate SSRF.
- Deploy runtime security monitoring to flag unexpected shell execution (e.g., 'sh', 'bash') initiated by Python processes.
