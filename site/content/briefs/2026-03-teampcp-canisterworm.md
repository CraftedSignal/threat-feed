---
title: TeamPCP Deploys CanisterWorm on NPM After Trivy Compromise
slug: 2026-03-teampcp-canisterworm
description: TeamPCP deployed the CanisterWorm malware on the NPM package registry following a compromise of the Trivy scanning tool.
date: "2026-03-22T10:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - malware
  - npm
  - canisterworm
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rzqm4i/teampcp_deploys_canisterworm_on_npm_following/
  - https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise
rules:
  - title: Suspicious NPM Package Installation
    description: Detects suspicious processes related to NPM package installation, potentially indicating CanisterWorm activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Child Process of NPM
    description: Detects potentially malicious child processes spawned by NPM, indicating command execution after an exploit.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On March 21, 2026, it was reported that threat actor TeamPCP successfully deployed CanisterWorm, a malicious worm, onto the NPM package registry. This followed a compromise of Trivy, a widely-used open-source vulnerability scanner. The specifics of the Trivy compromise are not detailed in this brief, but it likely involved exploiting vulnerabilities within Trivy or its infrastructure to gain unauthorized access and the ability to publish malicious packages. The scope of this incident affects developers and organizations that rely on NPM packages and utilize Trivy in their software development lifecycle. Defenders should prioritize detecting and mitigating the spread of CanisterWorm within their environments, focusing on identifying compromised Trivy instances and monitoring for suspicious activity related to NPM package installations.

## Attack Chain

1.  Initial Compromise: TeamPCP gains unauthorized access to Trivy infrastructure, potentially exploiting a vulnerability or using stolen credentials.
2.  Malware Injection: The attackers inject malicious code into a legitimate Trivy package or create a new package containing the CanisterWorm payload.
3.  NPM Deployment: TeamPCP publishes the compromised or new package to the NPM registry, making it available for download by unsuspecting users.
4.  Package Installation: Developers unknowingly download and install the malicious package through NPM, integrating CanisterWorm into their projects.
5.  Worm Propagation: CanisterWorm begins to propagate itself by infecting other NPM packages and dependencies within the compromised project.
6.  Lateral Movement: The worm replicates and spreads to other systems and projects that depend on the infected packages.
7.  Persistence: The malware establishes persistence within infected systems to maintain its presence and continue spreading.
8.  Payload Delivery: CanisterWorm executes its malicious payload, which could include data theft, code injection, or other harmful activities.

## Impact

The deployment of CanisterWorm on NPM poses a significant threat to the software supply chain. Successful infection can lead to widespread compromise of applications and systems that rely on NPM packages. The specific number of victims and the full extent of damage is currently unknown, but the incident has the potential to affect numerous organizations across various sectors that utilize NPM and Trivy in their development processes. Successful exploitation could result in data breaches, service disruptions, and reputational damage.

## Recommendation

*   Monitor NPM package installations for suspicious activity and unexpected dependencies to identify potential CanisterWorm infections.
*   Implement integrity checks for NPM packages to verify their authenticity and prevent the installation of tampered packages.
*   Analyze process creation events for suspicious processes originating from NPM-related processes using the provided Sigma rules.
*   Regularly scan systems for known malware signatures to detect CanisterWorm and other potential threats.
*   Review and strengthen the security of your software supply chain to mitigate the risk of future attacks.
