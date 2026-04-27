---
title: Axios npm Package Compromised in Supply Chain Attack
slug: 2026-03-axios-supply-chain
description: The widely used Axios npm package was compromised via a supply chain attack on March 31, 2026, resulting in the publication of malicious versions through a compromised maintainer account.
date: "2026-03-31T21:04:21Z"
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

On March 31, 2026 (UTC), the Axios npm package, a popular JavaScript library for making HTTP/S requests used by millions of applications, was targeted in a supply chain attack. A compromised maintainer account was used to publish malicious versions of the package, specifically axios@1.14.1 and axios@0.30.4, between approximately 00:21 and 03:30 UTC. This incident highlights the risks associated with software supply chains and the potential for attackers to inject malicious code into widely used…
