---
title: Spike in Number of Connections Made from a Source IP
slug: 2026-07-spike-in-rdp-connections
description: A machine learning detection rule identifies lateral movement by flagging an unusual spike in the number of destination IPs establishing Remote Desktop Protocol (RDP) connections with a single source IP, indicating an attacker attempting to expand access within the network to discover valuable assets or further access points.
date: "2026-07-28T18:09:23Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - lateral-movement
  - rdp
  - machine-learning
  - elastic-defend
vendors:
  - Elastic
products:
  - Elastic Defend (>= 8.18)
  - Lateral Movement Detection
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: A machine learning job has detected a high count of destination IPs establishing an RDP connection with a single source IP. Once an attacker has gained access to one system, they might attempt to access more in the network in search of valuable assets, data, or further access points.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: A machine learning job has detected a high count of destination IPs establishing an RDP connection with a single source IP.
    confidence_band: med
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/lmd
  - https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration
  - https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security
---

This brief details a machine learning detection rule from Elastic, designed to identify lateral movement activities within a network. The rule triggers when an anomalous spike is observed in the number of distinct destination IP addresses that a single source IP initiates Remote Desktop Protocol (RDP) connections to. This behavior often signifies that an attacker, having initially compromised a system, is attempting to expand their foothold by identifying and connecting to additional systems within the environment to locate valuable assets, exfiltrate data, or establish further access points. The detection leverages Elastic's anomaly detection capabilities and requires the Lateral Movement Detection integration and Elastic Defend to collect relevant RDP process events from Windows hosts. This rule is crucial for early identification of potential unauthorized access attempts and limiting an adversary's ability to move freely across the network.

## Attack Chain

1. **Initial Access**: An attacker gains initial access to an internal system within the target network through various means (e.g., phishing, exploiting a public-facing application).
2. **Internal Reconnaissance**: From the compromised system, the attacker performs internal reconnaissance to identify other potential target systems, often scanning for active RDP services.
3. **Credential Access**: The attacker obtains valid credentials for other systems through techniques like credential dumping, keylogging, or exploiting credential stores on the initial host.
4. **RDP Connection Attempts**: Using the compromised system as a pivot, the attacker initiates RDP connections to a large number of discovered internal hosts using the stolen credentials, aiming to find further exploitable systems.
5. **Successful RDP Sessions**: The attacker successfully establishes multiple RDP sessions with several internal hosts, indicating expanded access. This activity generates a spike in distinct RDP connections from the initial compromised source IP.
6. **Further Lateral Movement & Persistence**: The attacker utilizes the newly accessed systems to continue lateral movement, establish persistence, or conduct further reconnaissance to identify high-value targets.
7. **Objective Attainment**: The attacker executes their final objective, which could include data exfiltration, deployment of ransomware, or critical infrastructure disruption.

## Impact

If lateral movement through RDP goes undetected, attackers can significantly broaden their access within an organization's network. This can lead to the compromise of multiple sensitive systems, exfiltration of critical data, deployment of ransomware across numerous endpoints, or establishment of persistent access mechanisms. The undetected lateral movement allows adversaries to escalate privileges, discover and exploit high-value targets, and ultimately achieve their mission objectives with greater ease and impact, potentially leading to severe financial, reputational, and operational damage.

## Recommendation

* **Enable** the Lateral Movement Detection integration in Elastic Fleet, ensuring the `lmd_high_rdp_distinct_count_destination_ip_for_source_ea` machine learning job is deployed and active to detect anomalous RDP connection spikes.
* **Configure** Elastic Defend on all Windows endpoints (version 8.18 and above) to collect `host.ip` fields as outlined in Elastic's helper guide, which is essential for this rule's operation.
* **Review** and **whitelist** IP addresses associated with legitimate administrative tasks, automated network management tools, load balancers, proxy servers, security scans, or remote work solutions (VPNs) to reduce false positives, as mentioned in the rule's `false positive analysis` section.
* **Implement** network segmentation and strong access controls to limit RDP access to only necessary systems and users, minimizing the attack surface.
* **Establish** a process for reviewing alerts generated by the `Spike in Number of Connections Made from a Source IP` rule and follow the recommended investigation steps to quickly identify and respond to potential threats.
