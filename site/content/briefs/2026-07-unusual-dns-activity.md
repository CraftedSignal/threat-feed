---
title: Unusual DNS Activity Detected by Machine Learning
slug: 2026-07-unusual-dns-activity
description: An Elastic machine learning rule detects rare and unusual DNS queries that indicate potential malicious network activity, including initial access via phishing or malicious documents, persistence, command-and-control (C2) communication, or data exfiltration attempts by adversaries.
date: "2026-07-28T18:27:59Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - command-and-control
  - exfiltration
  - initial-access
  - machine-learning
  - network-traffic
  - dns-anomaly
  - elastic-security
  - endpoint-detection
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This can be due to initial access, persistence, command-and-control, or exfiltration activity. For example, when a user clicks on a link in a phishing email or opens a malicious document, a request may be sent to download and run a payload from an uncommon domain. When malware is already running, it may send requests to an uncommon DNS domain the malware uses for command-and-control communication.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1568
    technique_name: Dynamic Resolution
    evidence: A machine learning job detected a rare and unusual DNS query that indicate network activity with unusual DNS domains. ... When malware is already running, it may send requests to an uncommon DNS domain the malware uses for command-and-control communication.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: This can be due to initial access, persistence, command-and-control, or exfiltration activity.
    confidence_band: med
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: For example, when a user clicks on a link in a phishing email or opens a malicious document, a request may be sent to download and run a payload from an uncommon domain.
    confidence_band: high
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
---

This brief details the "Unusual DNS Activity" detection rule, powered by Elastic's machine learning capabilities, designed to identify atypical DNS queries that deviate significantly from a system's baseline behavior. Unidentified adversaries leverage rare or newly registered domains for various stages of an attack lifecycle, including initial access (e.g., distributing malware via phishing links), establishing persistent presence, maintaining command-and-control channels, or exfiltrating data. The rule analyzes network traffic and endpoint data collected by Elastic Defend or Network Packet Capture integrations to spot these anomalies. While not tied to a specific campaign or threat actor, this detection is critical for identifying covert communications that might bypass traditional signature-based security controls, signaling the presence of advanced malware or targeted attacks. This proactive detection helps defenders identify and mitigate potential compromises early in the attack chain.

## Attack Chain

1. **Initial Access**: Adversaries initiate an attack through vectors such as phishing emails containing malicious links or attachments, or by exploiting software vulnerabilities.
2. **Execution**: A victim interacts with the malicious content (e.g., clicking a link, opening a document), leading to the execution of attacker-controlled code or malware on the system.
3. **Callback/Payload Request**: The executed malicious code attempts to connect to attacker infrastructure to download additional payloads or establish an initial command-and-control (C2) channel.
4. **Rare DNS Query**: This communication involves making a DNS query to an uncommon, newly registered, or otherwise obscure domain specifically controlled by the attacker, which deviates from the system's normal DNS traffic patterns.
5. **Command and Control (C2)**: If successful, the malware periodically communicates with the attacker's infrastructure using these rare DNS domains for ongoing C2 instructions, updates, or tasking.
6. **Data Exfiltration**: In later stages, sensitive data may be encoded and transmitted out of the compromised network to attacker-controlled domains, potentially via DNS tunneling or other protocols using unusual DNS requests.

## Impact

Successful attacks involving unusual DNS activity can lead to a range of severe consequences. If the rare DNS query is part of an initial access attempt, it can lead to full system compromise, data theft, or ransomware deployment across the organization. For established C2 or data exfiltration, the impact includes sustained adversary presence within the network, intellectual property loss, financial damage, and reputational harm due to undetected breaches. The nature of these attacks, relying on statistically rare events, means they often indicate sophisticated adversaries bypassing standard defenses.

## Recommendation

* Deploy the "Unusual DNS Activity" machine learning job (ID: `rare_dns_question_ea`) in your Elastic Security environment to enable this anomaly detection rule.
* Ensure that data from Elastic Defend and Network Packet Capture integrations is properly configured and flowing into your Elastic Security app to provide the necessary log sources for the ML rule.
* When an alert triggers, review the DNS query logs to identify the specific rare domain that caused the alert and determine its reputation using available threat intelligence sources.
* Analyze the source IP address associated with the unusual DNS query to identify the affected device or user, and examine its network activity for any other anomalies.
* Implement whitelisting for legitimate internal applications or cloud services that are known to generate rare DNS queries to reduce false positives.
