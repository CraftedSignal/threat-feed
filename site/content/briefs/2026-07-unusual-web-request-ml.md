---
title: Unusual Web Request Detection via Machine Learning
slug: 2026-07-unusual-web-request-ml
description: Elastic's machine learning job identifies rare and unusual URLs accessed through web browsing or network traffic, signaling potential initial access, persistence, command-and-control, or data exfiltration activities that deviate from normal user behavior or legitimate application traffic patterns.
date: "2026-07-28T18:25:06Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - machine-learning-detection
  - network-traffic
  - command-and-control
  - initial-access
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: When malware is already running, it may send requests to uncommon URLs on trusted websites the malware uses for command-and-control communication.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: When malware is already running, it may send requests to uncommon URLs on trusted websites the malware uses for command-and-control communication.
    confidence_band: med
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: in a strategic web compromise or watering hole attack, when a trusted website is compromised to target a particular sector or organization, targeted users may receive emails with uncommon URLs for trusted websites.
    confidence_band: high
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
---

This brief details a machine learning-based detection rule developed by Elastic, designed to identify unusual web requests that could indicate malicious activity. Published on July 28, 2026, the rule leverages analytics on network traffic (Packetbeat) and endpoint data (Elastic Defend) to detect rare and statistically anomalous URLs. This capability is crucial for identifying early stages of compromise, such as initial access via watering hole attacks where trusted websites serve uncommon URLs for payload delivery, or advanced command-and-control (C2) communications by established malware. The detection also covers suspicious scanning, enumeration, or attack traffic directed at local web servers, including activity from bots and web scrapers, by flagging deviations from established web traffic baselines. This helps defenders proactively identify subtle indicators of compromise that might bypass signature-based detections.

## Attack Chain

[Attack Chain omitted as the source describes a detection capability for anomalous web activity rather than a specific, multi-step attack campaign.]

## Impact

If the detected unusual web requests are indeed malicious, the impact can range from initial system compromise, leading to persistent access for attackers, to the establishment of covert command-and-control channels, and potentially significant data exfiltration. Successful exploitation through such channels could result in loss of sensitive information, disruption of operations, or further propagation of malware within the network. While the rule itself does not describe specific victims or sectors, it aims to prevent these outcomes by flagging the anomalous activity before it escalates into a major incident.

## Recommendation

* Enable Elastic Defend integration and the Network Packet Capture integration to provide the necessary data inputs for the `Unusual Web Request` machine learning job.
* Deploy the `packetbeat_rare_urls_ea` machine learning job and ensure it is configured and running without errors.
* Review the `Unusual Web Request` alert details, focusing on the specific rare URL, associated IP addresses, and user agents to determine legitimacy.
* Correlate alerts with other security events and threat intelligence to identify broader attack campaigns or ongoing threats.
* Add identified legitimate rare web activity (e.g., technical support sites, internal web applications with unique transaction URLs) to an exclusion list to reduce false positives as described in the `false_positives` section.
