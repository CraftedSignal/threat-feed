---
title: Rapid7 Velociraptor Improper Input Validation Vulnerability
slug: 2024-01-02-velociraptor-rce
description: Rapid7 Velociraptor versions prior to 0.76.2 contain an improper input validation vulnerability allowing authenticated remote attackers to achieve remote code execution on the server.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - velociraptor
  - rce
  - input-validation
  - linux
vendors:
  - Rapid7
products:
  - Velociraptor
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5329
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5329
rules:
  - title: Detect Suspicious Velociraptor Server Process Execution
    description: Detects unusual process execution originating from the Velociraptor server, which could indicate exploitation of CVE-2026-5329.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Velociraptor Server Connection to Privileged Ports
    description: Detects Velociraptor server processes initiating connections to privileged ports, potentially indicating unauthorized activity after CVE-2026-5329 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Rapid7 Velociraptor, a tool used for endpoint detection and response, contains a critical vulnerability (CVE-2026-5329) affecting versions prior to 0.76.2. This vulnerability resides in the client monitoring message handler on the Velociraptor server, specifically impacting Linux deployments. An authenticated remote attacker can exploit this vulnerability by sending a crafted monitoring message with a malicious queue name. The insufficient input validation on the server side allows the attacker to write arbitrary messages to privileged internal queues. Successful exploitation can lead to remote code execution on the Velociraptor server. Note that Rapid7 Hosted Velociraptor instances are not affected. Defenders should prioritize patching vulnerable instances to version 0.76.2 or later to mitigate this risk.

## Attack Chain

1.  The attacker authenticates to the Velociraptor server.
2.  The attacker crafts a malicious monitoring message containing a payload.
3.  The malicious message is constructed with a specially crafted queue name targeting internal server queues.
4.  The attacker sends the crafted monitoring message to the Velociraptor server.
5.  The server's client monitoring message handler receives the message, but fails to properly validate the queue name.
6.  The attacker's message is written to the targeted privileged internal queue.
7.  The injected message triggers execution within the server's context.
8.  The attacker achieves remote code execution on the Velociraptor server.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the Velociraptor server. This can lead to complete compromise of the server, including data exfiltration, denial of service, and further lateral movement within the network. While the specific number of vulnerable instances is unknown, any organization using on-premise Velociraptor servers older than version 0.76.2 is at risk. This is especially impactful as Velociraptor is often deployed with elevated privileges to perform endpoint monitoring.

## Recommendation

*   Upgrade all Velociraptor server instances to version 0.76.2 or later to patch CVE-2026-5329.
*   Monitor Velociraptor server logs for unexpected writes to internal queues based on the description of the vulnerability.
*   Implement network segmentation to limit the impact of a compromised Velociraptor server.
*   Deploy the following Sigma rule to detect suspicious Velociraptor server process execution.
