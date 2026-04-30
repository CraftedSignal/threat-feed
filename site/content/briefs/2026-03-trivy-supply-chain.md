---
title: Trivy Scanner Compromised in Supply Chain Attack
slug: 2026-03-trivy-supply-chain
description: The widely used Trivy scanner has been compromised in an ongoing supply chain attack, potentially impacting numerous organizations using the tool for vulnerability management.
date: "2026-03-22T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - vulnerability-scanner
  - trivy
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://www.reddit.com/r/cybersecurity/comments/1rzznag/widely_used_trivy_scanner_compromised_in_ongoing/
  - https://arstechnica.com/security/2026/03/widely-used-trivy-scanner-compromised-in-ongoing/
rules:
  - title: Detect Suspicious Outbound Connection from Trivy
    description: Detects suspicious outbound network connections initiated by the Trivy scanner, which may indicate a compromise.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Trivy Execution
    description: Detects anomalous execution of the Trivy scanner, such as running from unusual directories or with suspicious command-line arguments.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On March 21, 2026, reports emerged indicating that the Trivy scanner, a popular open-source vulnerability scanner used extensively in software development and deployment pipelines, has been compromised in a supply chain attack. The specifics of the initial compromise vector remain under investigation, but the impact could be widespread due to Trivy's integration into numerous CI/CD systems and container registries. Organizations utilizing affected versions of Trivy risk deploying vulnerable or malicious containers and software builds, creating a significant security risk. The attackers' goals are currently unknown, but possibilities include injecting malware, stealing credentials, or gaining persistent access to compromised systems.

## Attack Chain

1.  The attacker gains unauthorized access to the Trivy project's build or distribution infrastructure (potentially via compromised credentials or a software vulnerability in the build process).
2.  The attacker injects malicious code into a release of the Trivy scanner. This could involve modifying existing binaries or libraries, or adding new malicious components.
3.  The compromised Trivy release is distributed to users through official channels, such as package managers or container registries.
4.  Developers and system administrators download and install the compromised Trivy scanner as part of their regular vulnerability scanning process.
5.  The malicious code within Trivy executes during scans, potentially allowing the attacker to gain initial access to the target system.
6.  The attacker uses the compromised Trivy scanner to establish a reverse shell connection to a command and control (C2) server.
7.  The attacker performs reconnaissance on the compromised system to identify sensitive data and potential targets.
8.  The attacker exfiltrates sensitive data, deploys ransomware, or performs other malicious activities depending on their objectives.

## Impact

The compromise of the Trivy scanner represents a significant supply chain risk. Given Trivy's widespread adoption, a successful attack could impact thousands of organizations across various sectors. The impact ranges from data breaches and financial losses due to ransomware to reputational damage and disruption of critical services. The exact number of affected organizations is currently unknown, but the potential scope is substantial.

## Recommendation

*   Implement network connection monitoring and deploy the Sigma rule "Detect Suspicious Outbound Connection from Trivy" to identify potentially compromised Trivy instances attempting to communicate with malicious C2 servers.
*   Monitor process creations and deploy the Sigma rule "Detect Suspicious Trivy Execution" to identify anomalies in Trivy execution behavior.
*   Implement integrity monitoring for Trivy binaries and configuration files to detect unauthorized modifications.
*   Conduct thorough security audits of your CI/CD pipelines and software supply chain to identify and mitigate potential vulnerabilities.
