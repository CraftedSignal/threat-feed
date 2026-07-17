---
title: Vect and TeamPCP Partner for Ransomware Campaigns Exploiting Supply Chain Compromises
slug: 2026-07-vect-teampcp-ransomware
description: The threat groups Vect and TeamPCP have formally partnered since March 2026 to conduct widespread ransomware deployment and extortion campaigns by leveraging TeamPCP's credential harvesting and data theft capabilities, often initiated through supply chain compromises involving poisoned software updates and exploitation of critical vulnerabilities like CVE-2025-55182, leading to significant data exfiltration and encrypted systems across multiple sectors.
date: "2026-07-02T12:00:57Z"
lastmod: "2026-07-17T00:01:39Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Vect
  - TeamPCP
tags:
  - ransomware
  - supply-chain-attack
  - data-theft
  - credential-access
  - extortion
  - python
  - github
  - pypi
vendors:
  - Meta
  - Aqua Security
  - Checkmarx
  - Bitwarden
  - BerriAI
  - Telnyx
  - Facebook
  - Vercel
products:
  - React Server Components
  - Trivy
  - Checkmarx KICS GitHub Action
  - Checkmarx AST GitHub Action
  - OpenVSX plugins
  - Bitwarden CLI
  - LiteLLM
  - Telnyx Python SDK
  - React (19.0.0, 19.1.0, 19.1.1, 19.2.0)
  - Next.js (15.x with App Router)
  - Next.js (16.0.0-16.0.6)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: TeamPCP first gained notoriety in December 2025 in connection with the mass exploitation of the React2Shell vulnerability (CVE-2025-55182), a critical (CVSS of 10.0) pre-authentication remote code execution flaw in React Server Components.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: From March through May 2026, TeamPCP made headlines for a series of high-profile supply chain attacks... simultaneously tampering with the core Trivy scanner program and its associated automation tools on GitHub and triggering the publication of a poisoned version of the software to official channels.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: TeamPCP published malicious versions of the Telnyx Python SDK (4.87.1 and 4.87.2) to PyPI... The malicious packages contained credential-harvesting payloads and Kubernetes-oriented lateral movement logic.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Version 1.82.8 included a file mechanism that triggered the payload automatically on Python interpreter startup, even without explicitly importing the package.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The malicious version silently harvested passwords, cloud credentials, and other sensitive secrets from the systems it ran on
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The malicious version silently harvested passwords, cloud credentials, and other sensitive secrets from the systems it ran on
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: A notable operational signature during this phase was the use of outbound port 666 for almost all network activity.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: transmitted that stolen data to attacker-controlled servers.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: if that primary channel failed, then the malware used the victim's GitHub credentials to create a hidden repository within that organization’s GitHub account and upload the stolen data there.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: Vect's ransomware deployment infrastructure in a widespread campaign involving supply chain attacks and the extortion of multiple organizations.
    confidence_band: high
references:
  - https://www.sophos.com/en-us/blog/vect-and-teampcp-partner-for-ransomware-campaigns
  - https://sploitus.com/exploit?id=C1F789DD-22F6-55CE-972A-C3B3E0305BF4&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=C1F789DD-22F6-55CE-972A-C3B3E0305BF4&utm_source=rss&utm_medium=rss
ioc_counts:
  url: 1
rules:
  - title: Detect TeamPCP Outbound Port 666
    description: Detects outbound network connections to port 666, which is a known operational signature for TeamPCP's C2 communications during their worm-driven campaigns.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.002
    data_sources:
      - network_connection
      - windows
rules_count: 1
updates:
  - at: "2026-07-17T00:01:39Z"
    level: L1
    summary: new IOCs
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=C1F789DD-22F6-55CE-972A-C3B3E0305BF4&utm_source=rss&utm_medium=rss
---

Since late March 2026, the interconnected threat groups Vect and TeamPCP have forged a formal operational partnership to amplify their ransomware and extortion campaigns. TeamPCP, also known as PCPcat, ShellForce, and DeadCatx3, specializes in credential harvesting and data theft, often initiating attacks through the mass exploitation of critical vulnerabilities such as the React2Shell vulnerability (CVE-2025-55182) in React Server Components, or by compromising development systems of widely used open-source tools like Trivy, Checkmarx, LiteLLM, and Telnyx. This allows them to inject malicious payloads into official software channels, leading to supply chain compromises. Vect, a ransomware-as-a-service (RaaS) operation that emerged in December 2025, then leverages the access and stolen credentials to deploy its ransomware, Vect 2.0, across victim networks. The combined operation impacts organizations in various sectors including technology, finance, healthcare, and government across North America, Europe, and Asia.

## Attack Chain

1.  **Initial Access & Vulnerability Exploitation**: TeamPCP gains initial access by exploiting critical public-facing application vulnerabilities (e.g., React2Shell, CVE-2025-55182) or compromising developer credentials through social engineering or other means, targeting supply chain components like development systems (e.g., Trivy's infrastructure) or CI/CD pipelines (e.g., LiteLLM, Telnyx).
2.  **Supply Chain Poisoning & Malicious Delivery**: Attackers inject malicious code into legitimate software updates (e.g., poisoned Trivy scanner, Checkmarx GitHub Actions, malicious PyPI packages for LiteLLM and Telnyx Python SDK) and publish them to official channels (e.g., GitHub, OpenVSX marketplace, PyPI).
3.  **Credential Harvesting & Data Collection**: When victims install the poisoned software, embedded payloads silently execute, harvesting sensitive information including passwords, cloud credentials, and other secrets from the compromised systems. Some payloads use novel techniques like WAV audio steganography.
4.  **Lateral Movement & Persistence**: Stolen credentials are used to spread self-propagating worms (e.g., CanisterWorm) across interconnected software packages or leverage Kubernetes-oriented lateral movement logic. Malicious packages may also establish persistence by triggering automatically on Python interpreter startup.
5.  **Command and Control (C2) & Exfiltration**: Harvested data is transmitted to attacker-controlled servers, often leveraging unusual outbound network activity (e.g., via port 666), or exfiltrated to hidden repositories within the victim's compromised cloud accounts (e.g., private GitHub repositories).
6.  **Ransomware Deployment & Extortion**: The access facilitated by TeamPCP's operations is then utilized by Vect's ransomware-as-a-service infrastructure to deploy the Vect 2.0 ransomware payload. Victims face data encryption, and stolen data (source code, API keys, employee details) is used on data leak sites (e.g., Vect's, Lapsus$ group's) for extortion.

## Impact

The partnership between Vect and TeamPCP has led to a significant increase in ransomware deployments and data theft incidents. Organizations in Canada, Serbia, South Korea, the UAE, and the United States, spanning technology, finance, healthcare, and government sectors, have been impacted. Successful attacks result in the encryption of critical systems, leading to operational disruption, and the exfiltration of highly sensitive data such as source code, API keys, database credentials, and employee details, which are subsequently used for extortion. The scale of the supply chain compromises means a single poisoned update can affect thousands of organizations, dramatically increasing the potential for widespread damage and financial loss.

## Recommendation

*   **Patch CVE-2025-55182 immediately** on all instances of React Server Components to prevent initial access.
*   **Deploy the Sigma rule `Detect TeamPCP Outbound Port 666`** to identify suspicious network connections indicative of TeamPCP C2 activity.
*   **Monitor outbound network connections** for unusual ports like 666, especially from development or build environments, using `network_connection` logs.
*   **Implement software supply chain security practices** to validate the integrity of third-party software updates and dependencies, especially from PyPI and GitHub.
*   **Review and audit permissions for GitHub Actions workflows** and OpenVSX plugins, ensuring least privilege and monitoring for unauthorized modifications.
*   **Enable comprehensive logging for process creation and network activity** to support the detection of malicious payloads harvesting credentials.
