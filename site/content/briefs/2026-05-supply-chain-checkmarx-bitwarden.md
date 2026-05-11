---
title: Supply Chain Attacks Target Checkmarx and Bitwarden Developer Tools
slug: 2026-05-supply-chain-checkmarx-bitwarden
description: On April 22, 2026, Checkmarx and Bitwarden suffered supply chain attacks where malicious versions of their developer tools were distributed through official channels, attempting to harvest sensitive information such as GitHub and npm tokens and exfiltrating data to audit.checkmarx[.]cx.
date: "2026-05-11T20:54:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - credential-theft
  - malware
vendors:
  - Checkmarx
  - Bitwarden
  - GitHub
  - npm
products:
  - KICS
  - cx-dev-assist
  - ast-results
  - '@bitwarden/cli'
  - Docker Hub
  - Open VSX
  - GitHub Actions
affected_os:
  - linux
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage Object
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.sophos.com/blog/supply-chain-attacks-hit-checkmarx-and-bitwarden-developer-tools
iocs:
  - type: domain
    value: audit.checkmarx[.]cx
ioc_counts:
  domain: 1
rules:
  - title: Detect Javascript Execution from Unusual Github URL
    description: Detects javascript execution via bun or node after being downloaded from a githubusercontent.com URL
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.007
      - T1105
    data_sources:
      - process_creation
      - windows
  - title: Detect Exfiltration to audit.checkmarx[.]cx
    description: Detects network connections to the audit.checkmarx[.]cx domain, potentially indicating exfiltration of stolen data.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1071
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On April 22, 2026, Checkmarx and Bitwarden experienced supply chain attacks where threat actors compromised their distribution channels to deliver malicious versions of their developer tools. Checkmarx KICS, a security scanner, was affected via tampered images on Docker Hub (tags v2.1.20-debian, v2.1.20, debian, alpine, latest, v2.1.21), malicious extensions on Open VSX (cx-dev-assist versions 1.17.0, 1.19.0 and ast-results versions 2.63.0, 2.66.0), and a malicious release on GitHub Actions (tag 2.3.35). The Bitwarden CLI was compromised with a trojanized version 2026.4.0 published to npm. The attackers aimed to steal credentials, including GitHub and npm tokens, SSH keys, cloud provider credentials, and AI assistant configurations, exfiltrating the data to audit.checkmarx[.]cx (94.154.172[.]43). These attacks highlight the risk of compromised software supply chains and the potential for widespread data theft.

## Attack Chain

1.  Attacker compromises the CI/CD pipeline or distribution channel of Checkmarx and Bitwarden.
2.  Malicious KICS images are pushed to Docker Hub with tampered Go binaries.
3.  Checkmarx extensions on Open VSX are modified to include a hidden 'MCP addon' feature, downloading and executing a payload from a hardcoded GitHub URL.
4.  A malicious release (2.3.35) is tagged on the ast-github-action repository.
5.  The trojanized @bitwarden/cli version 2026.4.0 is published to npm.
6.  The malicious payloads harvest sensitive information, including GitHub tokens, npm tokens, AWS/Azure/GCP credentials, SSH keys, environment variables, and AI configuration files.
7.  Stolen GitHub tokens are used to inject malicious workflows into victim repositories.
8.  Collected data is encrypted and exfiltrated to audit.checkmarx[.]cx.

## Impact

The attacks on Checkmarx and Bitwarden developer tools could have severe consequences. A stolen cloud credential or GitHub token from a developer's machine can be a foothold for an entire production infrastructure. The compromise of Bitwarden CLI could lead to exposure of stored passwords. Successful exfiltration of sensitive data from development environments allows attackers to access and control critical systems, potentially leading to data breaches, financial loss, and reputational damage. The Bitwarden CLI package draws more than 70,000 weekly downloads, indicating a potentially wide impact.

## Recommendation

*   Monitor network connections for outbound traffic to the C2 domain `audit.checkmarx[.]cx` (IOC - Domain).
*   Inspect running containers for the presence of tampered KICS images based on the affected Docker Hub tags (IOC - Docker Hub).
*   Implement integrity checks for dependencies installed via npm, specifically flagging the compromised `@bitwarden/cli` version 2026.4.0 (IOC - npm).
*   Deploy the Sigma rule to detect processes executing javascript downloaded from unusual github URLs.
*   Review GitHub Action workflows for suspicious modifications or injections using stolen tokens, as described in the attack chain.
