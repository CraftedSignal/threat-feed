---
title: High Confidence Command and Control Beaconing Detected by Statistical Model
slug: 2026-07-c2-beaconing-detection
description: This Elastic detection rule identifies high-confidence command-and-control (C2) beaconing activity, a technique allowing threat actors to maintain stealthy communication, receive instructions, exfiltrate data, and sustain persistence in compromised networks.
date: "2026-07-27T15:27:04Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - network
  - c2-beaconing
  - command-and-control
  - anomaly-detection
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Beaconing can help attackers maintain stealthy communication with their C2 servers, receive instructions and payloads, exfiltrate data and maintain persistence in a network.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: Beaconing can help attackers maintain stealthy communication with their C2 servers, receive instructions and payloads, exfiltrate data and maintain persistence in a network.
    confidence_band: high
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/beaconing
  - https://www.elastic.co/security-labs/identifying-beaconing-malware-using-elastic
---

This brief describes an Elastic Security detection rule designed to identify command-and-control (C2) beaconing activity with high confidence using a statistical model. C2 beaconing is a critical technique used by adversaries to maintain covert communication channels with compromised systems, enabling them to receive instructions, deploy additional payloads, exfiltrate sensitive data, and ensure persistence within a targeted network. The detection leverages Elastic's Network Beaconing Identification integration, which employs a statistical framework to analyze network logs and assign a beaconing score. A high score, specifically a `beacon_stats.beaconing_score` of 3, indicates a strong likelihood of malicious C2 activity. This detection capability requires the Elastic Defend integration for network log collection and a Fleet Server for the Network Beaconing Identification integration.

## Attack Chain

This brief describes a detection mechanism for command-and-control beaconing, not a full attack chain from initial access to impact. The detection occurs during the command and control phase of an attack.

## Impact

If C2 beaconing activity goes undetected, attackers can maintain a persistent foothold within the network, allowing for sustained control over compromised systems. This can lead to significant data exfiltration, deployment of further malicious payloads (such as ransomware or destructive malware), privilege escalation, and lateral movement across the organization's infrastructure. The long-term presence enabled by effective C2 communication can result in severe financial loss, reputational damage, and operational disruption.

## Recommendation

* Deploy the Network Beaconing Identification integration and Elastic Defend to collect the necessary network logs for the detection rule.
* Review the network traffic logs from the `ml_beaconing.all` index to investigate the source and destination IP addresses associated with detected beaconing activity.
* Correlate identified IP addresses and domain names with known malicious IP databases or threat intelligence feeds.
* Analyze the frequency and pattern of beaconing activity to assess alignment with typical C2 communication patterns.
* Examine payloads or data transferred during flagged communication sessions for sensitive information exfiltration or malicious instructions.
* Consult the investigation guide provided in the source material for detailed triage steps.
* Isolate affected systems from the network to prevent further communication with C2 servers and contain the threat.
* Conduct thorough analysis of network traffic logs to identify additional compromised systems or lateral movement within the network.
* Apply security patches and updates to all affected systems and change all associated credentials to prevent unauthorized access.
