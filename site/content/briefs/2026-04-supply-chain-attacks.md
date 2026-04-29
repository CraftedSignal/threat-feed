---
title: Rise in Software Supply Chain Attacks Targeting Open-Source Libraries
slug: 2026-04-supply-chain-attacks
description: Multiple supply chain attacks, including the compromise of Axios and Trivy via hijacked GitHub repositories by TeamPCP, demonstrate the increasing threat to open-source software.
date: "2026-04-03T17:31:42Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - software-compromise
  - github
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://blog.talosintelligence.com/protecting-supply-chain-2026/
  - https://blog.talosintelligence.com/axois-npm-supply-chain-incident/
  - https://blog.talosintelligence.com/2025yearinreview/
rules:
  - title: Detect Installation of Potentially Compromised Packages
    description: Detects the installation of a potentially compromised package based on package name. Modify the package names to match those affected by supply chain attacks.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - process_creation
      - windows
  - title: Detect CI/CD Pipeline Modifications
    description: Detects modifications to CI/CD pipeline configuration files, indicating potential tampering.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - file_event
      - linux
  - title: Detect ClamAV Detection of TeamPCP Trojan
    description: Detects file creation events related to files flagged by ClamAV as a TeamPCP Trojan.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1195.002
    data_sources:
      - file_event
      - windows
rules_count: 3
---

In early 2026, a surge in supply chain attacks has been observed, impacting widely used open-source libraries and tools. Notably, Axios, a popular HTTP client library for JavaScript with 100 million weekly downloads, was maliciously modified. Additionally, the "chaos-as-a-service" group TeamPCP injected malicious code into hijacked GitHub repositories for open-source projects, including Trivy, a security scanner. The Talos 2025 Year in Review indicated that nearly 25% of the top 100 targeted vulnerabilities affected widely used frameworks and libraries. React2Shell became the top-targeted vulnerability of 2025. These incidents highlight the fragility of the software supply chain and the potential for widespread downstream impact, affecting numerous organizations relying on these compromised components. Defenders face the challenge of identifying and remediating deeply integrated malicious code within their environments.

## Attack Chain

1.  **Initial Compromise:** TeamPCP compromises GitHub repositories of open-source projects like Trivy.
2.  **Code Injection:** Malicious code is injected into the project's codebase within the compromised GitHub repository.
3.  **Package Build and Distribution:** The compromised code is included in a new version of the software package during the build process.
4.  **Distribution via Package Managers:** The malicious package is distributed through package managers like npm, becoming available for download by developers.
5.  **Downstream Consumption:** Developers unknowingly download and integrate the compromised package into their applications.
6.  **Execution in Downstream Environments:** The malicious code executes within the developers' applications and environments.
7.  **Lateral Movement/Data Exfiltration/Ransomware:** The injected code performs malicious actions such as data exfiltration or establishing a reverse shell for lateral movement.
8.  **Impact:** The attacker achieves their objectives, such as data theft, system compromise, or ransomware deployment across numerous downstream victims.

## Impact

The compromise of widely used libraries and frameworks like Axios and Trivy can have a vast impact, potentially affecting millions of users and organizations. The Axios library alone receives 100 million downloads weekly. The successful exploitation of the React2Shell vulnerability demonstrates the speed at which these attacks can reach massive scale. The resulting damage can range from data breaches and system compromise to ransomware deployment, affecting organizations across various sectors. The integration of these utilities often makes full cataloging and remediation challenging, leading to prolonged exposure and increased risk.

## Recommendation

*   Secure CI/CD pipelines to prevent compromises from occurring, addressing the attack vector used by TeamPCP.
*   Implement robust logging to monitor for suspicious activity related to compromised packages and aid in incident response.
*   Organizations must inventory the software libraries and frameworks they employ and rapidly implement patching and other mitigations when security incidents are reported.
*   Implement robust multi-factor authentication (MFA) to protect developer accounts on platforms like GitHub.
