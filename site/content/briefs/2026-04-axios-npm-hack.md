---
title: Axios npm Package Compromised via Social Engineering
slug: 2026-04-axios-npm-hack
description: North Korean threat actors (UNC1069) compromised the Axios npm package by socially engineering a maintainer with a fake Microsoft Teams update delivering a RAT, leading to the injection of a malicious dependency and a supply chain attack.
date: "2026-04-04T20:30:42Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - UNC1069
tags:
  - supply chain attack
  - npm
  - social engineering
  - rat
  - unc1069
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
  - tactic_id: TA0009
    tactic_name: Supply Chain Compromise
    technique_id: T1199
    technique_name: Trusted Relationship
references:
  - https://www.bleepingcomputer.com/news/security/axios-npm-hack-used-fake-teams-error-fix-to-hijack-maintainer-account/
rules:
  - title: Detect Suspicious NPM Package Installation
    description: Detects npm package installations initiated by unusual parent processes, which may indicate a supply chain attack or compromised developer environment.
    platform: sigma
    severity: medium
    tactics:
      - supply_chain
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious plain-crypto-js Dependency
    description: Detects the installation or use of the plain-crypto-js dependency.
    platform: sigma
    severity: high
    tactics:
      - supply_chain
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On April 4, 2026, the maintainers of the Axios HTTP client disclosed a social engineering attack targeting one of their developers. The attack, attributed to the North Korean threat actor UNC1069, involved impersonating a legitimate company to build trust with the targeted developer. The attacker used a fake Microsoft Teams update disguised as a critical error fix to deploy a remote access trojan (RAT). This RAT allowed the attackers to gain access to the developer's system and npm credentials. The attackers then published two malicious versions of Axios (1.14.1 and 0.30.4) to the npm package registry. These malicious versions included a dependency called plain-crypto-js, which installed a RAT on macOS, Windows, and Linux systems. These versions were available for three hours, posing a supply chain risk to any systems that installed them during that period.

## Attack Chain

1.  The attacker identifies a target developer and initiates contact via LinkedIn/Slack, impersonating a legitimate company.
2.  The attacker invites the developer to a Slack workspace populated with fake profiles and staged company activity.
3.  A meeting is scheduled on Microsoft Teams, during which a fake "RTC Connection" error message is displayed.
4.  The attacker prompts the developer to install a "Teams update" to resolve the error.
5.  The fake update is a RAT malware, granting the attacker remote access to the developer's machine.
6.  The attacker steals the developer's npm credentials, bypassing MFA due to already authenticated session.
7.  The attacker publishes malicious versions of the Axios package (1.14.1 and 0.30.4) to the npm registry, injecting the plain-crypto-js dependency.
8.  Systems installing the compromised Axios versions download and execute the plain-crypto-js package, resulting in RAT deployment and credential theft.

## Impact

The compromise of the Axios npm package created a supply chain attack impacting an unknown number of systems across various sectors. Systems that installed the malicious versions (1.14.1 and 0.30.4) within the three-hour window are considered compromised. Successful exploitation results in the installation of a remote access trojan (RAT) capable of stealing credentials, browser data, and other sensitive information from macOS, Windows, and Linux systems. This can lead to further unauthorized access, data breaches, and potential financial loss.

## Recommendation

*   Monitor npm package installations for the presence of the plain-crypto-js dependency, particularly in projects that use Axios versions 1.14.1 or 0.30.4.
*   Implement multi-factor authentication (MFA) for npm accounts and other developer accounts, but recognize that authenticated sessions can be hijacked.
*   Deploy the Sigma rule "Detect Suspicious NPM Package Installation" to detect potentially malicious package installations based on unusual parent processes (see below).
*   Block the domain associated with the malicious dependency plain-crypto-js at the DNS resolver.
*   Educate developers about social engineering tactics and the risks of installing software from untrusted sources.
