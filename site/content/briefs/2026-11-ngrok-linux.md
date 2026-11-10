---
brief_id: brief-2026-11-10-ngrok-linux
event_id: brief-2026-11-10-ngrok-linux
revision: 1
activity_at: "2026-11-10T03:34:11Z"
title: Ngrok Tunneling Service Usage on Linux
slug: 2026-11-ngrok-linux
description: This brief documents the detection of outbound network connections to ngrok tunneling infrastructure, which can be utilized for unauthorized remote access or data exfiltration.
date: "2026-11-10T03:34:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic verified against source
tags:
  - exfiltration
  - command-and-control
  - linux
  - network-security
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Detects an executable accessing an ngrok tunneling endpoint, which could be a sign of forbidden exfiltration of data exfiltration by malicious actors
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: Detects an executable accessing an ngrok tunneling endpoint
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/linux/network_connection/net_connection_lnx_ngrok_tunnel.yml
rules:
  - title: Detect Outbound Connection to Ngrok
    description: Detects processes establishing outbound connections to known ngrok tunnel endpoints
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1567
      - T1572
    data_sources:
      - network_connection
      - linux
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify processes making outbound connections to *.ngrok.com
      technique_id: T1567
      data_needed:
        - Netflow or process-to-destination network logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source notes potential for malicious actor use of tunneling infrastructure
---

Ngrok is a legitimate tool often used for exposing local services to the internet via secure tunnels. Threat actors may leverage ngrok to establish unauthorized Command and Control (C2) channels or exfiltrate data from compromised Linux environments. This detection focuses on identifying network connections originating from within the environment to known ngrok tunneling service endpoints.

## Recommendation

* Deploy the Sigma rule below to detect outbound connectivity to ngrok tunneling domains.
* Establish a baseline for authorized ngrok usage within the organization to reduce noise.
* Utilize network-layer telemetry to audit processes initiating connections to ngrok infrastructure.
