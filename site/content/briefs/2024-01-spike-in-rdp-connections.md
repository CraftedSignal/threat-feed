---
title: Spike in Number of RDP Connections from a Single Source IP
slug: 2024-01-spike-in-rdp-connections
description: A machine learning job detected a high count of destination IPs establishing RDP connections with a single source IP, indicating potential lateral movement attempts after initial compromise.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - lateral-movement
  - rdp
  - elastic
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/lmd
  - https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration
  - https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security
rules:
  - title: Detect RDP Connection to Multiple Hosts from Single Source
    description: Detects a single host initiating RDP connections to multiple distinct internal IP addresses, indicative of lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - network_connection
      - windows
  - title: Detect RDP Client Executing from Uncommon Location
    description: Detects RDP client executable (mstsc.exe) running from an unusual directory, which may indicate malicious execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1021.001
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the potential for lateral movement within a network facilitated by an unusual spike in Remote Desktop Protocol (RDP) connections originating from a single source IP address. This activity is detected using an Elastic machine learning job designed to identify anomalies in network connection patterns. The rule "Spike in Number of Connections Made from a Source IP" leverages this ML job to flag instances where a single host initiates RDP connections to a significantly higher than normal number of distinct destination IPs, potentially indicating that an attacker is attempting to pivot and gain access to additional systems after compromising an initial foothold. This detection mechanism is available in Elastic Security 9.4.0 and later, with the Lateral Movement Detection integration assets installed.

## Attack Chain

1. **Initial Compromise:** An attacker gains initial access to a host within the network through methods such as phishing, exploiting a vulnerability, or credential theft.
2. **Establish Foothold:** The attacker establishes a foothold on the compromised system, potentially installing tools for reconnaissance and lateral movement.
3. **Internal Reconnaissance:** The attacker performs internal reconnaissance to identify potential target systems accessible via RDP.
4. **RDP Connection Attempts:** The attacker initiates RDP connections to a large number of internal IP addresses from the compromised host.
5. **Credential Harvesting:** The attacker attempts to harvest credentials from the targeted systems to gain further access.
6. **Lateral Movement:** The attacker successfully connects to additional systems using RDP, leveraging harvested or stolen credentials.
7. **Privilege Escalation:** On newly accessed systems, the attacker attempts to escalate privileges to gain administrative control.
8. **Objective Completion:** With broader access and elevated privileges, the attacker achieves their objective, which may include data exfiltration, ransomware deployment, or disruption of services.

## Impact

If successful, this lateral movement can result in widespread compromise across the targeted network. A single compromised host can serve as a launching point to access sensitive data, critical systems, and ultimately, inflict significant damage. The "Spike in Number of Connections Made from a Source IP" rule aims to detect these lateral movement attempts early, minimizing potential damage. The impact of a successful attack could range from data breaches and financial losses to operational disruption and reputational damage, affecting organizations across various sectors.

## Recommendation

*   Enable host IP collection if using Elastic Defend (versions 8.18 and above), by following the configuration steps outlined in the Elastic documentation to ensure the `host.ip` field is populated.
*   Install the Lateral Movement Detection integration assets as described in the [official Elastic documentation](https://docs.elastic.co/en/integrations/lmd).
*   Review and tune the false positive analysis steps within the detection rule's documentation. Whitelist known administrative IPs or legitimate RDP usage patterns to minimize noise.
*   Implement network segmentation to limit RDP access to only necessary systems and users, reducing the attack surface as recommended in the rule's response and remediation guidance.
