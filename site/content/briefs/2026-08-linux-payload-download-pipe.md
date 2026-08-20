---
title: Linux Payload Download and Execution via Interpreter Pipes
slug: 2026-08-linux-payload-download-pipe
description: Attackers utilize network utilities curl or wget to download remote payloads and pipe them directly into system interpreters to execute malicious code in memory or from non-standard locations.
date: "2026-08-20T19:06:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers may use this technique to download and execute payloads for various malicious purposes.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This rule detects when a file is downloaded by curl or wget, and piped to an interpreter.
    confidence_band: high
rules:
  - title: Detect Payload Downloaded by Curl/Wget and Piped to Interpreter
    description: Detects the use of curl or wget to download a remote resource, followed by the immediate execution of that resource by a system interpreter, which is indicative of malicious code execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1071
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the payload download detection rule to SIEM environment.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides specific logic for detecting this TTP.
  hunt_leads:
    - lead: Search for command lines containing both a download utility and a pipe to an interpreter.
      technique_id: T1059.004
      data_needed:
        - process_creation
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Rule documentation explicitly identifies this pattern.
  mitigation_plan:
    - priority: medium_term
      action: Restrict outbound internet access from sensitive servers to only allowlisted domains.
      owner: IT Operations
      addresses: C2 execution via curl/wget
      evidence: Reduces likelihood of successful payload retrieval.
---

This threat involves attackers using common network utilities, specifically curl and wget, to download remote payloads and pipe them directly into system interpreters such as bash, python, or node. This technique is a standard method for threat actors to achieve code execution, establish persistence, or exfiltrate data while attempting to evade traditional file-based security controls. By keeping the payload in memory or executing it directly from a pipe, the attacker reduces their on-disk footprint, making detection more reliant on process lineage and behavioral analysis. Defenders should monitor for process executions where curl or wget are spawned from shells or suspicious working directories, followed by the immediate invocation of an interpreter. This activity is prevalent in Linux environments and is often associated with initial access or post-exploitation stages where the attacker is retrieving secondary tools or scripts from command-and-control infrastructure.

## Impact

Successful execution of this technique allows an attacker to achieve arbitrary code execution on a compromised Linux host. This can lead to full system compromise, data exfiltration, or the installation of persistent backdoors. The technique is frequently seen across all sectors that manage Linux infrastructure, particularly in environments with internet-facing workloads. The primary risk is the bypass of traditional antivirus or file-integrity monitoring, as the malicious code is never written to disk in a standard, recognizable file format before execution.

## Recommendation

Prioritize the deployment of behavioral detection rules that monitor for the combination of network downloads and subsequent interpreter invocation in a single process chain.

* Deploy detection logic to monitor for processes spawned by curl or wget that execute within one second of the download event.
* Enable process-creation logging (such as Elastic Defend or Sysmon for Linux) to capture the full command-line arguments and process parent-child relationships.
* Ensure that shells and interpreters are monitored for unusual parent processes, specifically those originating from /tmp or /var/tmp directories.
* Tune detections to filter out legitimate administrative tasks or known-good deployment scripts that utilize curl or wget to fetch software packages from trusted, allowlisted URLs.
