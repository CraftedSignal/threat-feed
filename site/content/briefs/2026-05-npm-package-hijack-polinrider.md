---
title: Hijacked npm Package Attempts to Deliver PolinRider-Linked RAT
slug: 2026-05-npm-package-hijack-polinrider
description: Attackers are compromising npm packages to distribute a RAT linked to PolinRider, directly injecting malicious code into the software supply chain.
date: "2026-05-21T20:53:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - supply-chain
  - npm
  - rat
  - polinrider
vendors:
  - Sonatype
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1610
    technique_name: Exploitation of Supply Chain
references:
  - https://www.sonatype.com/blog/hijacked-npm-package-attempts-to-deliver-polinrider-linked-rat
rules:
  - title: Detect Suspicious npm Package Installation
    description: Detects installation of packages from npm with unexpected install scripts
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1610
    data_sources:
      - process_creation
      - linux
  - title: Detect npm Package Hijacking - Suspicious File Creation
    description: Detects unusual file creation by npm processes, potentially indicating a hijacked package executing malicious code.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Attackers are increasingly targeting the software supply chain by hijacking npm packages. This allows them to insert malicious code directly into projects during the build process, bypassing traditional vulnerability exploitation routes that rely on CVEs. While the specific hijacked package is not named in this brief, the attack involves injecting a Remote Access Trojan (RAT) associated with the PolinRider threat actor. This technique is particularly effective because developers often implicitly trust packages from established repositories like npm, making it easier for malicious code to be unknowingly included in their applications. This type of attack can have wide-ranging consequences, impacting numerous downstream users and organizations.

## Attack Chain

1. Attackers compromise an existing npm package, likely through stolen credentials or social engineering.
2. Malicious code is injected into the package, potentially obfuscated to avoid detection.
3. The compromised package is published to the npm repository, replacing the legitimate version.
4. Developers unknowingly install the malicious package or update to the compromised version.
5. During the build process, the injected code executes on the developer's machine.
6. The malicious code establishes a connection to a command-and-control (C2) server.
7. The PolinRider-linked RAT is downloaded and installed on the compromised system.
8. The RAT grants the attacker remote access to the infected machine, enabling data theft, further malware deployment, or other malicious activities.

## Impact

Compromised npm packages can lead to widespread infections across numerous projects and organizations that depend on the affected package. Successful attacks can result in data breaches, system compromise, and supply chain disruption. The injection of a PolinRider-linked RAT enables attackers to gain persistent remote access to infected systems, potentially impacting sensitive development environments and production deployments. The full extent of the impact depends on the popularity and usage of the hijacked package.

## Recommendation

*   Implement strong authentication and access controls for npm package maintainers to prevent account compromise.
*   Enable and review npm's two-factor authentication (2FA) for all maintainer accounts.
*   Implement software composition analysis (SCA) tools to monitor dependencies and detect suspicious changes in npm packages.
*   Regularly audit dependencies for known vulnerabilities and malicious code.
*   Monitor network traffic for connections to known PolinRider infrastructure.
