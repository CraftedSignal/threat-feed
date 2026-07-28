---
title: Host Detected with Suspicious Windows Processes via Machine Learning
slug: 2026-07-host-suspicious-windows-process-ml
description: Elastic's machine learning job, utilizing the ProblemChild supervised model and unsupervised techniques, detects Windows hosts exhibiting clusters of suspicious processes with unusually high malicious probability scores, often indicative of defense evasion through Living Off The Land Binaries (LOLbins) and masquerading techniques.
date: "2026-07-28T18:23:04Z"
lastmod: "2026-07-28T18:30:16Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - masquerading
  - lolbins
  - machine-learning
  - windows
  - ml-detection
  - endpoint-security
vendors:
  - Elastic
products:
  - Elastic Defend
  - Elastic Agent
  - Fleet
  - Kibana
  - Network Packet Capture
  - Auditd Manager
  - Elastic Stack >= 9.4.0
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The detection leverages machine learning to identify clusters of Windows processes with high malicious probability scores. Adversaries exploit legitimate tools, known as LOLbins, to evade detection. This rule uses both supervised and unsupervised ML models to flag unusual process clusters on a single host, indicating potential masquerading tactics for defense evasion.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Adversaries exploit legitimate tools, known as LOLbins, to evade detection. This rule uses both supervised and unsupervised ML models to flag unusual process clusters on a single host, indicating potential masquerading tactics for defense evasion.
    confidence_band: high
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/problemchild
  - https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/command_and_control_ml_dns_tunneling.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/discovery_ml_linux_system_network_configuration_discovery.toml
updates:
  - at: "2026-07-28T18:24:31Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/ml/command_and_control_ml_dns_tunneling.toml
  - at: "2026-07-28T18:30:16Z"
    level: L1
    summary: OS linux
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/ml/discovery_ml_linux_system_network_configuration_discovery.toml
---

This threat brief describes an Elastic machine learning (ML) detection rule designed to identify hosts exhibiting suspicious Windows process activity indicative of defense evasion. The rule leverages a combination of Elastic's ProblemChild supervised ML model and unsupervised ML techniques to flag clusters of processes with unusually high malicious probability scores. Attackers frequently use Living Off The Land Binaries (LOLbins) and masquerading tactics to evade traditional signature-based detections. This ML-driven approach is designed to catch such sophisticated behaviors by identifying anomalous process clusters that may involve legitimate system tools being used maliciously. The detection aims to provide early warning for potential compromise by highlighting activity that might otherwise go unnoticed by conventional security rules.

## Attack Chain

This brief describes a machine learning detection mechanism for identifying suspicious process behavior rather than a specific, linear attack chain. The detection targets various stages where attackers might employ defense evasion techniques, such as using LOLbins or process masquerading. The rule aims to identify the *outcome* of such techniques on a Windows host, which could occur during initial access, execution, persistence, or privilege escalation phases of an attack. The specific methods leading to these suspicious processes are diverse and depend on the adversary's chosen TTPs, but the ML model identifies the resulting anomalous process clusters.

## Impact

Failure to detect and respond to the suspicious process clusters flagged by this ML rule can lead to successful defense evasion by attackers. If adversaries successfully employ LOLbins and masquerading, they can establish persistence, escalate privileges, move laterally, and exfiltrate data without triggering conventional security alerts. The ultimate impact can include data breaches, ransomware deployment, system damage, and significant operational disruption, as the initial signs of compromise through these evasive techniques were not addressed.

## Recommendation

* **Enable the LotL Attack Detection integration**: Ensure the Living off the Land Attack Detection integration is correctly installed and configured in your Elastic environment, as detailed in the "Setup" section, to enable the underlying ML jobs.
* **Install Elastic Defend or Winlogbeat**: Collect Windows process events using either Elastic Defend or Winlogbeat, as specified in the "Setup" section, to feed the necessary data to the ML jobs.
* **Review affected hosts**: Upon detection, review the host name associated with the suspicious process cluster to determine its criticality and history, as described in the "Investigating Host Detected with Suspicious Windows Process(es)" guide.
* **Examine flagged processes and command lines**: Investigate the specific processes and their command-line arguments flagged by the ProblemChild supervised ML model to identify known LOLbins or unusual usage patterns, as suggested in the "Investigating Host Detected with Suspicious Windows Process(es)" guide.
* **Investigate parent-child process relationships**: Examine the parent-child relationships of the processes to identify any unexpected or unauthorized process spawning, as recommended in the "Investigating Host Detected with Suspicious Windows Process(es)" guide.
* **Correlate with other security events**: Correlate the alert with other security events or logs from the same host to identify additional indicators of compromise, as outlined in the "Investigating Host Detected with Suspicious Windows Process(es)" guide.
