---
brief_id: brief-2026-11-17-macos-curl-abuse
event_id: brief-2026-11-17-macos-curl-abuse
revision: 1
activity_at: "2026-11-17T14:57:06Z"
title: Suspicious Curl from macOS Application
slug: 2026-11-macos-curl-abuse
description: Threat actors use trojanized macOS applications from the /Applications directory to invoke curl or nscurl for payload retrieval, potentially bypassing Gatekeeper quarantine checks.
date: "2026-11-17T14:57:06Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.001
    subtechnique_name: Web Protocols
    evidence: Trojanized macOS applications often use curl to download second-stage payloads from attacker-controlled infrastructure.
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This detection rule identifies when applications from the /Applications directory spawn curl to connect to raw IP addresses, which is highly indicative of malicious payload retrieval activity.
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
    subtechnique_id: T1553.001
    subtechnique_name: Gatekeeper Bypass
    evidence: By leveraging curl instead of direct downloads, these malicious applications can bypass Gatekeeper quarantine checks and evade built-in macOS security mechanisms.
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/command_and_control_suspicious_curl_from_macos_application.toml
  - https://objective-see.org/blog/blog_0x71.html#-vpn-trojan-covid
  - https://attack.mitre.org/techniques/T1105/
rules:
  - title: Suspicious Curl from macOS Application
    description: Detects the use of curl or nscurl by a macOS application binary to connect to a raw IP URI and download a second stage payload.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1105
      - T1553.001
    data_sources:
      - process_creation
      - macos
rules_count: 1
---

## Overview
Threat actors utilize trojanized macOS applications to download second-stage payloads from attacker-controlled infrastructure. By leveraging 'curl' or 'nscurl' instead of direct downloads, these malicious applications can bypass Gatekeeper quarantine checks and evade built-in macOS security mechanisms. This detection rule identifies when applications residing in the /Applications directory spawn 'curl' or 'nscurl' processes, specifically when the parent process is a shell or interpreter, to connect to raw IP addresses.

## Attack Chain
1. A macOS application in the /Applications directory acts as a parent process (or ancestor).
2. A shell or interpreter (bash, sh, zsh, osascript, tclsh, or python) acts as the immediate parent process for the network tool.
3. The 'curl' or 'nscurl' process is executed to download a payload from a raw IP address using specified download arguments.

## Impact
Successful exploitation allows the retrieval of malicious payloads while evading built-in macOS security mechanisms designed to verify downloaded content.

## Recommendation
- Review the process.Ext.effective_parent.executable field to identify the originating application.
- Examine process.args to extract the destination IP and URL path.
- Analyze the process.parent.command_line to understand the full context of the execution.
- Check the code signature of the parent application.
- Inspect system logs for file creation and correlated execution events to identify if the payload was executed.
