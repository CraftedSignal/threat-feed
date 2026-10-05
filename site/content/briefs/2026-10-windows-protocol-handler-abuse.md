---
title: Abuse of Windows Protocol Handlers for Code Execution
slug: 2026-10-windows-protocol-handler-abuse
description: Attackers can exploit custom or native Windows protocol handlers to execute arbitrary commands, maintain persistence, or escalate privileges by abusing URI-based application launching.
date: "2026-10-05T18:02:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - execution
  - persistence
  - privilege-escalation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can leverage custom or existing protocol handlers to execute arbitrary code, escalate privileges, or maintain persistence on a target system.
    confidence_band: high
references:
  - https://gist.github.com/MHaggis/a0d3edb57d36e0916c94c0a464b2722e
  - https://github.com/Mr-Un1k0d3r/PoisonHandler
  - https://www.mdsec.co.uk/2021/03/phishing-users-to-take-a-test/
  - https://www.huntress.com/blog/microsoft-office-remote-code-execution-follina-msdt-bug
rules:
  - title: Detect Suspicious Protocol Handler Execution
    description: Detects the execution of processes via command line that match known suspicious protocol handler patterns.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy protocol handler detection logic and tune for benign browser activity
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic guidance on process-based hunting
  hunt_leads:
    - lead: Search for suspicious process creation events containing '://' in the command line
      technique_id: T1059
      data_needed:
        - Process creation logs with command line
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source explicitly describes using process and command-line telemetry to identify protocol handler abuse
  mitigation_plan:
    - priority: medium_term
      action: Review and remove unused custom URI protocol handlers from the registry
      owner: IT Operations
      addresses: T1059
      evidence: Source implies registry-based persistence and execution vectors
---

Windows protocol handlers are designed to allow applications to register a URI scheme (such as ms-word: or custom application handlers) that launches a specific binary when invoked. Threat actors exploit this mechanism by registering malicious handlers or abusing existing ones to achieve arbitrary code execution. This technique is often categorized under Living off the Land (LotL) activities, as it leverages built-in system functionality to bypass security controls. 

Defenders must monitor command-line telemetry for processes spawned in response to protocol handler activation. Because common handlers like http and https are legitimate, high-volume activity is expected, requiring baseline tuning to identify anomalous execution patterns. This technique has been historically associated with various payloads, including malware distribution and remote code execution vulnerabilities. Monitoring for these handlers provides visibility into early-stage delivery or persistence mechanisms.

## Attack Chain

1. Attacker identifies a target application or creates a custom protocol handler entry in the Windows Registry under HKEY_CLASSES_ROOT.
2. Attacker crafts a malicious URI (e.g., scheme://payload) to be delivered via phishing, malicious documents, or web content.
3. User clicks the malicious URI link, triggering the system to resolve the handler to a specific executable path.
4. The operating system shells out to the associated handler binary, passing the crafted URI parameters as command-line arguments.
5. The handler binary executes, inadvertently processing the attacker-controlled input.
6. If the handler is vulnerable to command injection, the target process performs unauthorized actions, such as downloading additional payloads or spawning shells.
7. Final objective is reached, such as gaining initial access, establishing persistence, or achieving privilege escalation via the compromised process context.

## Impact

Abuse of protocol handlers can lead to unauthorized code execution, persistence, and privilege escalation on the host. This technique is frequently used in phishing campaigns and remote exploitation scenarios, potentially leading to full system compromise depending on the privileges of the application handling the URI.

## Recommendation

Prioritize the identification of abnormal process launches initiated via protocol handler schemes.

* Ingest Sysmon Event ID 1 or Windows Event ID 4688 logs into your SIEM, ensuring command-line arguments are captured.
* Map process execution telemetry to the Endpoint data model using the Splunk Common Information Model (CIM) to enable behavioral analytics.
* Deploy detection logic to flag unusual processes being launched by common browser or office-related protocol handlers.
* Tune detections by filtering out established legitimate application behavior, such as standard http/https browser launches, to reduce false positives.
