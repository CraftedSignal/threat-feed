---
title: GitHub Exfiltration via High Number of Repository Clones
slug: 2026-06-github-exfiltration
description: A single user rapidly cloning a high number of GitHub repositories indicates potential exfiltration of sensitive data such as proprietary code, embedded secrets, and build artifacts.
date: "2026-04-10T17:40:11Z"
severities:
  - medium
tags:
  - github
  - exfiltration
  - code_repository
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
references:
  - https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
  - https://trigger.dev/blog/shai-hulud-postmortem
  - https://posthog.com/blog/nov-24-shai-hulud-attack-post-mortem
  - https://attack.mitre.org/techniques/T1020/
  - https://attack.mitre.org/techniques/T1567/
  - https://attack.mitre.org/techniques/T1567/001/
  - https://attack.mitre.org/techniques/T1213/
  - https://attack.mitre.org/techniques/T1213/003/
rules:
  - title: Github Exfiltration via High Number of Clones in Short Time
    description: Detects a user rapidly cloning multiple GitHub repositories, indicating potential data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.001
    data_sources:
      - webserver
      - linux
  - title: Github Token Usage with High Number of Clones
    description: Detects a GitHub token being used to clone a large number of repositories, indicating potential exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This alert identifies potential data exfiltration from GitHub via rapid repository cloning. Attackers often target code repositories to steal proprietary code, embedded secrets, and build artifacts. This activity can be indicative of a compromised personal access token (PAT) being used in a script to enumerate and clone repositories from a CI runner or cloud VM. Private and internal repositories are particularly attractive targets, as they often contain sensitive information. The alert focuses…
