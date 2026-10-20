---
brief_id: brief-2026-10-potential-powershell-obfuscation
event_id: brief-2026-10-potential-powershell-obfuscation
revision: 1
activity_at: "2026-10-20T16:24:55Z"
title: Potential PowerShell Obfuscated Script via High Entropy
slug: 2026-10-potential-powershell-obfuscation
description: Detection of PowerShell script blocks utilizing high-entropy character distributions to mask obfuscated, compressed, or encrypted malicious payloads.
date: "2026-10-20T16:24:55Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - windows
  - defense-evasion
  - powershell
vendors:
  - Microsoft
products:
  - PowerShell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    subtechnique_id: T1027.010
    subtechnique_name: Command Obfuscation
    evidence: Attackers may obfuscate PowerShell scripts using encoding, encryption, or compression techniques to evade signature-based detections.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
    evidence: Look for transformation and staging patterns and whether transformed content is immediately executed.
    confidence_band: high
rules:
  - title: Detect PowerShell Script Blocks with High Entropy
    description: Detects PowerShell script blocks exhibiting high entropy and non-uniform character distribution, indicative of obfuscated or encrypted payloads.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1027
      - T1027.010
      - T1140
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints.
      owner: IT Operations
      due: 48h
      evidence: Source requires PowerShell logging telemetry.
  hunt_leads:
    - lead: Identify high-entropy PowerShell execution events not associated with known administrative scripts.
      technique_id: T1027
      data_needed:
        - PowerShell Script Block logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: High entropy blocks are statistically significant indicators of obfuscation.
---

Adversaries frequently employ PowerShell to execute malicious commands, often leveraging obfuscation, compression, or encryption to evade signature-based security controls and manual inspection. This intelligence highlights a method for identifying such scripts by analyzing the statistical properties of PowerShell Script Block logs (Event ID 4104). By measuring Shannon entropy, surprisal standard deviation, and unique symbol counts, security teams can flag script blocks that deviate from the patterns of standard, human-readable code. This detection is particularly effective at surfacing in-memory loaders and staged payloads that attempt to hide their functionality through non-uniform character sets. While high-entropy blocks can occasionally originate from legitimate administrative tools, tuning the detection through filtering of authorized paths and users allows defenders to surface high-risk staging activity.

## Attack Chain

1. Attacker develops a malicious payload or loader script designed for in-memory execution.
2. Attacker applies obfuscation (Base64 encoding, XOR encryption, or Gzip compression) to the script body to prevent static analysis.
3. The obfuscated script is staged on disk or directly injected into a PowerShell process via an external trigger (e.g., macro, remote command).
4. The PowerShell engine logs the script block content via Event ID 4104 as it is processed for execution.
5. The security monitoring tool identifies the block due to its high entropy metrics (bits > 5.5).
6. The adversary's de-obfuscation routine (embedded within the script) executes to decode the payload in memory.
7. The final stage malicious payload (e.g., beacon or lateral movement tool) executes in memory to achieve the attacker's objective.

## Impact

Successful execution of obfuscated PowerShell scripts allows adversaries to achieve initial access, execute arbitrary code, maintain persistence, and facilitate lateral movement while minimizing the risk of detection by standard security solutions. By bypassing signature-based inspection, attackers can increase the dwell time of their operations within a target environment.

## Recommendation

* Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to ensure the necessary telemetry is available for analysis.
* Deploy the provided Sigma rule (or equivalent logic) to monitor for high-entropy PowerShell execution.
* Baseline administrative PowerShell activity to identify and filter out legitimate high-entropy scripts originating from known internal automation paths.
* When an alert occurs, pivot on `powershell.file.script_block_id` to reconstruct fragmented scripts and inspect for loading logic that precedes dynamic execution.
