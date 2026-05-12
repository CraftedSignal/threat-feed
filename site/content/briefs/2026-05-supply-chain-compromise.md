---
title: Compromised OpenSearch Pre-Release npm Packages in Supply Chain Attack
slug: 2026-05-supply-chain-compromise
description: Multiple npm and PyPi packages, including OpenSearch pre-release packages, were compromised in a supply chain attack, potentially leading to arbitrary code execution on developer or user systems.
date: "2026-05-12T22:01:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain-compromise
  - npm
  - pypi
products:
  - OpenSearch
  - PyPi packages
  - npm packages
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://seclists.org/oss-sec/2026/q2/510
  - https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
  - https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
rules:
  - title: Detect Suspicious Outbound Connection from Build Server
    description: Detects suspicious outbound network connections from build servers, potentially indicating a compromised dependency.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Package Installation
    description: Detects suspicious package installation commands, potentially indicating a supply chain attack.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1195
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 12, 2026, a supply chain attack was disclosed affecting multiple npm and PyPi packages, including pre-release versions of OpenSearch. The attackers compromised these packages by injecting malicious code, potentially impacting developers and users who installed the affected versions. This incident highlights the increasing risk of supply chain attacks targeting open-source software repositories. The compromised packages could allow attackers to execute arbitrary code on systems where the packages were installed, leading to data theft, system compromise, or further propagation of malware. This incident is part of a broader campaign referred to as "Mini Shai Hulud" which targeted hundreds of packages. Defenders should prioritize identifying and removing affected packages from their environments.

## Attack Chain

1.  Attacker compromises developer accounts or package maintainer credentials.
2.  Malicious code is injected into the OpenSearch pre-release npm packages.
3.  Compromised packages are published to the npm and PyPi repositories.
4.  Developers or automated build systems download and install the infected packages as part of their build process using `npm install` or `pip install`.
5.  The malicious code executes on the developer's machine or build server, potentially establishing a reverse shell or downloading further payloads.
6.  The malicious code might inject itself into other project dependencies or build artifacts.
7.  Applications built with the compromised packages are deployed to production environments, infecting end-user systems.
8.  Attackers gain remote access to infected systems, enabling data exfiltration, lateral movement, and other malicious activities.

## Impact

This supply chain attack could impact a large number of developers and users who rely on the compromised OpenSearch pre-release packages. Successful exploitation allows attackers to execute arbitrary code on affected systems, leading to data breaches, system compromise, and potentially widespread disruption. Hundreds of packages were affected across NPM and PyPi. The impact could range from minor inconvenience to severe data loss and reputational damage.

## Recommendation

*   Implement strict dependency management policies, including the use of package lockfiles (package-lock.json, yarn.lock, Pipfile.lock) to ensure consistent and verifiable builds.
*   Utilize software composition analysis (SCA) tools to identify and remediate vulnerable dependencies in your projects.
*   Monitor network connections originating from build servers and development environments for suspicious activity using the "Detect Suspicious Outbound Connection from Build Server" Sigma rule below.
*   Consider implementing sandboxing or containerization technologies to isolate build processes and limit the impact of compromised dependencies.
*   Audit your existing npm and PyPi dependencies for the compromised packages identified in the Wiz.io and Socket.dev blog posts.
*   Deploy the "Detect Suspicious Package Installation" Sigma rule to detect potentially malicious package installation commands.
