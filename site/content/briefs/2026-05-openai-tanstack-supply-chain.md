---
title: OpenAI Compromised via TanStack Supply Chain Attack
slug: 2026-05-openai-tanstack-supply-chain
description: OpenAI was impacted by the TanStack supply chain attack, resulting in two employee devices being compromised and the exfiltration of credential material from internal source code repositories.
date: "2026-05-15T10:37:19Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - credential-access
  - npm
  - pypi
vendors:
  - OpenAI
products:
  - macOS applications
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
references:
  - https://www.securityweek.com/openai-hit-by-tanstack-supply-chain-attack/
rules:
  - title: Detect Shai-Hulud Worm Infection
    description: Detects potential Shai-Hulud worm infection activity based on process creation events. This worm was used in the TanStack supply chain attack that compromised OpenAI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
  - title: Detect macOS Application Update Attempts Post Compromise
    description: Detects attempts to update macOS applications after the certificate revocation date, which may indicate malicious activity. Targets updates of OpenAI applications after June 12, 2026.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - file_event
      - macos
rules_count: 2
---

On May 11, 2026, the open-source web application development stack TanStack was compromised, leading to a coordinated campaign that saw over 170 packages across NPM and PyPI namespaces being infected. The TeamPCP hacking group exploited weaknesses in the package publishing process to release 84 malicious artifacts across 42 packages, resulting in developer devices being infected with the Shai-Hulud worm. OpenAI was one of the affected organizations, with two employee devices being compromised, leading to the exfiltration of credentials and other secrets from internal source code repositories. Although the scope of the compromise was limited, the attackers gained access to several internal source code repositories.

## Attack Chain

1.  The TeamPCP group exploited vulnerabilities in the TanStack package publishing process.
2.  Malicious artifacts were released across 42 packages, resulting in 84 malicious packages.
3.  Over 170 packages across several high-profile NPM and PyPI namespaces were compromised.
4.  Developer devices were infected with the Shai-Hulud worm.
5.  Two OpenAI employee devices were infected as part of the supply chain attack.
6.  Credential material was exfiltrated from internal source code repositories.
7.  Attackers gained access to code-signing certificates for iOS, macOS, Windows, and Android products.
8.  OpenAI is revoking certificates and re-signing applications to mitigate the impact.

## Impact

The compromise of two OpenAI employee devices resulted in the exfiltration of credential material, including code-signing certificates for iOS, macOS, Windows, and Android products. Although no customer data or intellectual property was affected, OpenAI is revoking the compromised certificates and requiring macOS users to update their applications by June 12, 2026, to prevent the potential distribution of fake applications. Failure to update macOS applications will result in the products ceasing to receive updates and potentially malfunctioning.

## Recommendation

*   Monitor for unauthorized use of code-signing certificates related to OpenAI products (macOS applications, iOS, macOS, Windows, Android products) on internal networks.
*   Deploy the Sigma rule detecting Shai-Hulud worm-related activity to identify potential infections within the environment.
*   Review notarization logs for software signed using previous OpenAI certificates to confirm no unauthorized modifications have occurred, as mentioned in the overview.
