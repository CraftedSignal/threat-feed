---
title: Halfbaked Malware Command and Control Beaconing Detected
slug: 2026-07-halfbaked-c2
description: FIN7 is leveraging Halfbaked malware to establish persistence and conduct command and control (C2) operations within compromised networks, using HTTP and TLS protocols with specific URL structures (e.g., `http://[IP_ADDRESS]/cd`) and common ports (53, 80, 8080, 443) for detection evasion and data exfiltration.
date: "2026-07-20T12:19:42Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - FIN7
  - Carbon Spider
  - Sangria Tempest
tags:
  - command-and-control
  - malware
  - halfbaked
  - fin7
  - network-traffic
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Halfbaked malware exploits common network protocols to maintain persistence and facilitate command and control (C2) operations within compromised networks. Adversaries leverage HTTP and TLS protocols to disguise malicious traffic as legitimate, often targeting specific ports like 53, 80, 8080, and 443.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1568
    technique_name: Dynamic Resolution
    evidence: The detection rule identifies suspicious network patterns, such as unusual URL structures (e.g., http://[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/cd) [...] The detection rule identifies suspicious network patterns, such as unusual URL structures and specific transport protocols, to flag potential C2 beaconing activities.
    confidence_band: high
references:
  - https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html
  - https://attack.mitre.org/software/S0151/
  - https://github.com/elastic/detection-rules/blob/main/rules/network/command_and_control_halfbaked_beacon.toml
iocs:
  - type: url
    value: http://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/cd
ioc_counts:
  url: 1
rules:
  - title: Halfbaked Malware Command and Control Beaconing
    description: Detects network activity patterns indicative of Halfbaked malware C2 beaconing, specifically HTTP/TLS traffic to an IP address followed by '/cd' on common web ports.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071
      - T1071.001
      - T1568
      - T1568.002
    data_sources:
      - network_connection
rules_count: 1
---

Halfbaked is a malware family employed by the threat actor FIN7 to establish persistence and facilitate command and control (C2) within compromised networks. This malware leverages standard network protocols, specifically HTTP and TLS, to masquerade its malicious traffic as legitimate activity. It often targets common ports such as 53 (DNS, but also used for HTTP), 80, 8080, and 443, making its detection challenging. A key indicator of Halfbaked's C2 beaconing activity is the use of distinct network patterns, particularly unusual URL structures like `http://[IP_ADDRESS]/cd`. This specific pattern allows defenders to identify potential compromises and ongoing C2 communications. The activity has been documented in FIN7 campaigns, indicating its use by a sophisticated financial threat group.

## Impact

Successful compromise by Halfbaked malware leads to established persistence within the victim's network, enabling long-term command and control capabilities for FIN7. This allows the threat actor to maintain a foothold, execute arbitrary commands, and potentially exfiltrate sensitive data. Victims may suffer significant financial losses, data breaches, and operational disruptions. The primary objective is likely data theft for financial gain, consistent with FIN7's historical targeting of financial and retail sectors. The continued presence of the malware can lead to deeper network penetration and broader system compromise.

## Recommendation

* Deploy the Sigma rule provided in this brief to your SIEM and tune it for your environment to detect Halfbaked C2 beaconing.
* Review network traffic logs to investigate any connections to IP addresses matching the `http://[IP_ADDRESS]/cd` pattern, as identified in the `iocs` section, to determine if they are known or suspicious.
* Analyze destination ports (53, 80, 8080, 443) used in flagged traffic to assess alignment with typical usage patterns for affected systems.
* Correlate detected network activity with endpoint logs to identify any associated processes or applications that initiated suspicious traffic, using `network_connection` and `process_creation` log sources.
* Block the malicious URL patterns mentioned in the `iocs` section at the network perimeter or egress points to prevent further C2 communication.
* Isolate affected systems from the network immediately to prevent further communication with C2 servers and conduct thorough malware scans.
