---
title: Compromised SAP npm Packages Steal Developer Credentials
slug: 2026-04-sap-npm-compromise
description: Multiple official SAP npm packages were compromised via a supply chain attack, likely by TeamPCP, to steal credentials and authentication tokens from developers' systems.
date: "2026-04-29T22:43:44Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - TeamPCP (Likely)
tags:
  - supply-chain
  - credential-theft
  - npm
vendors:
  - SAP
products:
  - Cloud Application Programming Model (CAP)
  - Cloud MTA
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1609
    technique_name: Supply Chain Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1609
    technique_name: Supply Chain Compromise
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1609
    technique_name: Supply Chain Compromise
references:
  - https://www.bleepingcomputer.com/news/security/official-sap-npm-packages-compromised-to-steal-credentials/
rules:
  - title: Detect Suspicious NPM Package Preinstall Script
    description: Detects the execution of suspicious commands from a 'preinstall' script within an npm package installation, indicative of a supply chain attack.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1027
      - T1609
    data_sources:
      - process_creation
      - linux
  - title: Detect GitHub Repository Creation with 'A Mini Shai-Hulud has Appeared' Description
    description: Detects the creation of a GitHub repository with the description 'A Mini Shai-Hulud has Appeared', which is a potential indicator of data exfiltration by the TeamPCP malware.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On April 29, 2026, security researchers discovered that multiple official SAP npm packages were compromised in a supply-chain attack, suspected to be carried out by TeamPCP. The compromised packages, including `@cap-js/sqlite` (v2.2.2), `@cap-js/postgres` (v2.2.2), `@cap-js/db-service` (v2.10.1), and `mbt` (v1.2.48), support SAP's Cloud Application Programming Model (CAP) and Cloud MTA, commonly used in enterprise development. The attack involves injecting a malicious 'preinstall' script into these packages, which executes automatically during installation. This script downloads and executes a heavily obfuscated JavaScript payload designed to steal sensitive credentials from developer machines and CI/CD environments. This incident highlights the ongoing risk of supply chain attacks targeting widely used development tools.

## Attack Chain

1.  **Initial Compromise:** Threat actors compromise official SAP npm packages (`@cap-js/sqlite`, `@cap-js/postgres`, `@cap-js/db-service`, `mbt`). The exact method of initial compromise is currently unknown, but a misconfigured CircleCI job is suspected.
2.  **Package Modification:** The compromised npm packages are modified to include a malicious 'preinstall' script.
3.  **Installation Trigger:** When developers install the compromised packages using `npm install`, the 'preinstall' script executes automatically.
4.  **Payload Download:** The 'preinstall' script launches a loader named `setup.mjs` that downloads the Bun JavaScript runtime from GitHub.
5.  **Execution of Information Stealer:** The Bun runtime is used to execute a heavily obfuscated `execution.js` payload, which acts as an information stealer.
6.  **Credential Theft:** The information stealer targets a wide variety of credentials, including npm and GitHub authentication tokens, SSH keys, cloud credentials for AWS, Azure, and Google Cloud, Kubernetes configurations and secrets, and CI/CD pipeline secrets and environment variables.  It also attempts to extract secrets directly from the CI runner's memory by scanning `/proc/<pid>/maps` and `/proc/<pid>/mem`.
7.  **Data Exfiltration:** The stolen data is encrypted and uploaded to public GitHub repositories under the victim's account. These repositories include the description "A Mini Shai-Hulud has Appeared".
8.  **Lateral Movement:** The malware searches GitHub commits for the string `OhNoWhatsGoingOnWithGitHub:<base64>`, decoding matching commit messages into GitHub tokens to gain further access and propagate to other packages and repositories, injecting the same malicious code.

## Impact

This supply chain attack can lead to the theft of sensitive credentials, allowing attackers to gain unauthorized access to internal systems, cloud infrastructure, and source code repositories. The compromised credentials and secrets can be used for lateral movement within the victim's network, data exfiltration, and further supply chain attacks. The use of stolen credentials to modify other packages increases the scope of the attack, potentially impacting a large number of developers and organizations using the compromised SAP packages.

## Recommendation

*   Monitor npm package installations for the presence of `preinstall` scripts executing unusual processes, such as the execution of `setup.mjs` or the download of the Bun JavaScript runtime from GitHub; implement the `Detect Suspicious NPM Package Preinstall Script` Sigma rule.
*   Implement the `Detect GitHub Repository Creation with "A Mini Shai-Hulud has Appeared" Description` Sigma rule to detect exfiltration attempts via public GitHub repositories.
*   Audit CI/CD pipeline configurations and restrict access to sensitive credentials and secrets to prevent exposure via misconfigured jobs; remediate the reported CircleCI misconfiguration.
*   Monitor process memory for credential harvesting activity targeting Runner processes in CI/CD environments, specifically looking for reads of `/proc/<pid>/maps` and `/proc/<pid>/mem` as outlined in the overview.
*   Deprecate and remove the compromised packages `@cap-js/sqlite` (v2.2.2), `@cap-js/postgres` (v2.2.2), `@cap-js/db-service` (v2.10.1), and `mbt` (v1.2.48) from your development and CI/CD environments.
