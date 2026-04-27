---
title: Elastic Defend Alert from Package Manager Install Ancestry
slug: 2026-04-package-manager-ancestry
description: This rule detects Elastic Defend alerts where the alerted process has a package-manager install context in its ancestry (npm, PyPI, Rust), indicating potential supply chain compromise via malicious postinstall scripts.
date: "2026-04-11T12:00:00Z"
severities:
  - critical
tags:
  - supply-chain
  - initial-access
  - package-manager
  - elastic-defend
  - post-install
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://attack.mitre.org/techniques/T1195/
  - https://attack.mitre.org/techniques/T1195/002/
rules:
  - title: Suspicious Process Ancestry with NPM Install
    description: Detects processes spawned from NPM install commands which may indicate malicious post-install scripts
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1195
      - T1195.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Ancestry with PIP Install
    description: Detects processes spawned from PIP install commands which may indicate malicious packages
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1195
      - T1195.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Ancestry with Cargo Install
    description: Detects processes spawned from Cargo commands which may indicate malicious packages
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1195
      - T1195.002
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection rule identifies Elastic Defend alerts triggered by processes with a package manager installation context in their ancestry. This includes package managers such as npm (Node.js), PyPI (pip / Python / uv), and cargo (Rust). The rule is designed to detect supply chain attacks and post-install abuse, where malicious scripts are executed during or after package installation. The rule leverages Elastic Defend alerts to identify suspicious activity within the process tree of package…
