---
title: Cisco Secure Firewall - High Volume of Intrusion Events Per Host
slug: 2026-05-cisco-high-intrusion-events
description: This analytic detects internal systems generating an unusually high volume of intrusion detections within a 30-minute window using Cisco Secure Firewall Threat Defense logs, identifying hosts triggering more than 15 Snort-based signatures, which may indicate suspicious activity like malware execution, command-and-control communication, vulnerability scanning, or lateral movement.
date: "2026-05-28T17:44:03Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - network
  - intrusion_detection
  - anomaly_detection
vendors:
  - Cisco
  - Splunk
products:
  - Secure Firewall Threat Defense
  - Splunk Enterprise
  - Splunk Cloud
  - Splunk Enterprise Security
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/FQE/secure_firewall_estreamer_fqe_guide_740.pdf
rules:
  - title: Cisco Secure Firewall - High Volume of Intrusion Events Per Host
    description: Detects internal systems that generate an unusually high volume of intrusion detections within a 30-minute window.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - discovery
      - execution
    techniques:
      - T1059
      - T1071
      - T1595.002
    data_sources:
      - firewall
      - cisco
  - title: Cisco Secure Firewall - Intrusion Events with Specific Signatures
    description: Detects specific intrusion events based on signature IDs observed in high-volume alerts.  Can be used to pivot from the high-volume detection to identify specific attacker activity.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - discovery
      - execution
    data_sources:
      - firewall
      - cisco
rules_count: 2
---

This analytic detects internal systems generating an unusually high volume of intrusion detections within a 30-minute window. It leverages Cisco Secure Firewall Threat Defense logs, specifically focusing on the IntrusionEvent event type, to identify hosts that trigger more than 15 Snort-based signatures during that time. A sudden spike in intrusion alerts originating from a single host may indicate suspicious or malicious activity such as malware execution, command-and-control communication, vulnerability scanning, or lateral movement. In some cases, this behavior may also be caused by misconfigured or outdated software repeatedly tripping detection rules. Systems exhibiting this pattern should be triaged promptly, as repeated Snort rule matches from a single source are often early indicators of compromise, persistence, or active exploitation attempts. The detection utilizes the Splunk Add-on for Cisco Security Cloud.

## Attack Chain

1. An attacker gains initial access to an internal system, potentially through phishing or exploiting a vulnerability.
2. The compromised system begins scanning the internal network for vulnerable services (T1595.002).
3. The vulnerability scanning triggers multiple Snort intrusion detection signatures on the Cisco Secure Firewall.
4. Malware executes on the compromised system, attempting to establish command and control communication (T1071).
5. The command and control communication generates network traffic patterns that match Snort signatures.
6. The attacker attempts lateral movement to other systems on the network (T1059).
7. Each attempt to move laterally triggers additional intrusion events.
8. The Cisco Secure Firewall logs these IntrusionEvent events, which are aggregated and analyzed by Splunk.

## Impact

A successful attack can lead to data exfiltration, system compromise, and disruption of services. A high volume of intrusion events originating from a single host may indicate that an attacker has gained a foothold within the network and is actively engaged in malicious activity. This can result in significant financial losses, reputational damage, and legal liabilities. The longer the attacker remains undetected, the greater the potential for damage.

## Recommendation

*   Ensure the Cisco Secure Firewall Threat Defense is properly configured to log IntrusionEvent events as described in the [Cisco documentation](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/FQE/secure_firewall_estreamer_fqe_guide_740.pdf).
*   Install and configure the Splunk Add-on for Cisco Security Cloud to ingest the Cisco Secure Firewall Threat Defense logs.
*   Deploy the Sigma rule `Cisco Secure Firewall - High Volume of Intrusion Events Per Host` to your Splunk environment and tune the threshold (TotalEvents >= 15) based on your environment.
*   Investigate any systems that trigger a high volume of intrusion events, focusing on potential malware infections, unauthorized access, and vulnerability scanning.
*   Use the provided drilldown searches to view the detection results and risk events associated with the source IP address.
