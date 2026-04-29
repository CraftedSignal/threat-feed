---
title: Axios npm Package Compromised in Supply Chain Attack
slug: 2026-03-axios-supply-chain
description: The widely used Axios npm package was compromised via a supply chain attack on March 31, 2026, resulting in the publication of malicious versions through a compromised maintainer account.
date: "2026-03-31T21:04:21Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - supply-chain
  - npm
  - javascript
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
references:
  - https://arcticwolf.com/resources/blog/supply-chain-attack-impacts-widely-used-axios-npm-package/
rules:
  - title: Detect Suspicious Process Execution from Axios
    description: Detects suspicious process execution originating from applications using the Axios library, potentially indicating exploitation of the compromised package.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Modified Axios Package Files
    description: Detects modifications to Axios package files, potentially indicating tampering or malicious code injection.
    platform: sigma
    severity: medium
    tactics:
      - integrity
    techniques:
      - T1565.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

On March 31, 2026 (UTC), the Axios npm package, a popular JavaScript library for making HTTP/S requests used by millions of applications, was targeted in a supply chain attack. A compromised maintainer account was used to publish malicious versions of the package, specifically axios@1.14.1 and axios@0.30.4, between approximately 00:21 and 03:30 UTC. This incident highlights the risks associated with software supply chains and the potential for attackers to inject malicious code into widely used components, impacting countless downstream applications. Defenders should prioritize monitoring their dependencies and implementing measures to detect and prevent such attacks.

## Attack Chain

1.  **Compromise Maintainer Account:** An attacker gains unauthorized access to the credentials of an Axios npm package maintainer.
2.  **Publish Malicious Package Versions:** The attacker uses the compromised account to publish malicious versions of the Axios package (axios@1.14.1 and axios@0.30.4) to the npm registry.
3.  **Dependency Resolution:** Developers or automated build systems unknowingly download and incorporate the malicious Axios versions into their projects during dependency resolution.
4.  **Malicious Code Execution:** The malicious code within the Axios package executes within the context of the affected applications.
5.  **Privilege Escalation (If Applicable):** Depending on the vulnerabilities exploited, the attacker may attempt to escalate privileges within the compromised environment.
6.  **Data Exfiltration/Lateral Movement:** The attacker uses the compromised application as a beachhead to exfiltrate sensitive data or move laterally to other systems on the network.
7.  **Establish Persistence:** The attacker establishes persistent access to the compromised environment to maintain control.
8.  **Achieve Objectives:** The attacker achieves their ultimate objectives, which could include data theft, system disruption, or further compromise of the software supply chain.

## Impact

This supply chain attack on the Axios npm package has the potential to affect millions of applications that depend on the library. Successful exploitation could lead to data breaches, unauthorized access to systems, and widespread disruption of services. The exact scope of the impact depends on the nature of the malicious code injected into the Axios package and the vulnerabilities it exploits.

## Recommendation

*   Monitor npm package installations for the presence of axios@1.14.1 and axios@0.30.4 and investigate any occurrences (refer to the **Overview** section).
*   Implement integrity checks for npm packages to detect unauthorized modifications to dependencies.
*   Deploy the provided Sigma rule to detect suspicious process execution within applications using the Axios library (see **rule: "Detect Suspicious Process Execution from Axios"**).
