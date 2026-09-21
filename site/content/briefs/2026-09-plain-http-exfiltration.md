---
title: Detection of Data Exfiltration via Plain HTTP POST Requests
slug: 2026-09-plain-http-exfiltration
description: Adversaries and malware, including Trickbot and APT actors, leverage plain HTTP POST requests to exfiltrate sensitive system information, such as process lists and network configurations, to remote C2 infrastructure.
date: "2026-09-21T19:13:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - data-exfiltration
  - command-and-control
  - network-security
  - web
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: The analytic monitors for suspicious keywords or process names found within the HTTP form data fields of network traffic.
    confidence_band: high
rules:
  - title: Detect Suspicious Plaintext HTTP POST Exfiltration
    description: Detects potential data exfiltration via HTTP POST where the form body contains known malicious enumeration strings or suspicious process identifiers.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1048.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for HTTP POST body monitoring
      owner: Detection Engineering
      due: 48h
      evidence: Source detection logic for T1048.003
  hunt_leads:
    - lead: Search for high-volume POST requests to unknown external IPs
      technique_id: T1048
      data_needed:
        - Network traffic logs including bytes_out
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Adversaries use plain text HTTP POST requests for exfiltration
---

This threat brief focuses on the use of unencrypted HTTP POST requests as a channel for data exfiltration and command-and-control (C2) communication. Malicious actors, ranging from commodity malware like Trickbot to sophisticated APT adversaries, frequently embed sensitive data within HTTP form fields to bypass security controls that may be primarily focused on more complex protocols. By sending plain text requests containing artifacts such as process lists ("proclist"), network configuration ("ipconfig", "net view"), or system information ("sysinfo"), attackers can silently extract environment details. Defenders should monitor network traffic for HTTP POST methods where the request body contains strings associated with enumeration tools or suspicious process names like "wermgr.exe" or "svchost.exe". This detection logic is critical for identifying unauthorized data staging and C2 heartbeats occurring in cleartext.

## Attack Chain

1. The malware or adversary identifies sensitive system or network information to exfiltrate.
2. The attacker executes local commands, such as "ipconfig" or "net view", to collect environment context.
3. The collected output is captured or formatted into a string for transmission.
4. The malicious binary initiates an outbound network connection to a remote C2 server using an HTTP POST request.
5. The captured system data is placed within the HTTP form data field of the POST request.
6. The request is transmitted in plain text, bypassing transport-layer encryption.
7. The C2 server receives and logs the exfiltrated data, completing the exfiltration objective.

## Impact

Successful exploitation allows for the covert exfiltration of sensitive organizational information, potentially facilitating further network infiltration, credential theft, or the delivery of secondary payloads. This activity is a hallmark of persistent threats and large-scale information-stealing campaigns that compromise host-level security.

## Recommendation

Detection engineering teams should focus on network-layer monitoring of HTTP traffic bodies.

* Deploy the Sigma rule below to monitor for suspicious keywords in HTTP POST bodies.
* Ensure that network logging solutions (e.g., Splunk Stream or similar PCAP-to-metadata tools) are configured to capture the `http-request-body` or equivalent payload fields.
* Investigate any detected `src_ip` generating such traffic to identify the source process and determine if it is a sanctioned application or unauthorized malware.
