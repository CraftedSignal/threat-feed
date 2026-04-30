---
title: GitHub Exfiltration via High Number of Repository Clones
slug: 2026-06-github-exfiltration
description: A single user rapidly cloning a high number of GitHub repositories indicates potential exfiltration of sensitive data such as proprietary code, embedded secrets, and build artifacts.
date: "2026-04-10T17:40:11Z"
type: advisory
types:
  - advisory
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

This alert identifies potential data exfiltration from GitHub via rapid repository cloning. Attackers often target code repositories to steal proprietary code, embedded secrets, and build artifacts. This activity can be indicative of a compromised personal access token (PAT) being used in a script to enumerate and clone repositories from a CI runner or cloud VM. Private and internal repositories are particularly attractive targets, as they often contain sensitive information. The alert focuses on detecting unusual patterns of bulk cloning within a short timeframe, allowing defenders to respond quickly before significant data loss occurs. The original rule was created on 2025/12/16 and updated on 2026/04/10. This activity is often associated with supply chain attacks and the compromise of CI/CD pipelines, similar to the Shai Hulud attacks.

## Attack Chain

1.  Attacker gains unauthorized access to a GitHub account or obtains a valid, but misused, Personal Access Token (PAT).
2.  The attacker uses the compromised credentials to authenticate to the GitHub API.
3.  The attacker script enumerates accessible repositories within the organization, identifying potential targets.
4.  A script is executed to initiate a high volume of `git clone` operations against the targeted repositories.
5.  Repositories, including private and internal ones, are cloned to a staging area, often a CI runner or cloud VM.
6.  The cloned data is compressed and staged for exfiltration, potentially involving archiving or large outbound transfers.
7.  The attacker exfiltrates the cloned data to an external location, potentially via a web service or other covert channel.
8.  The exfiltrated data is used for malicious purposes, such as reverse engineering, finding vulnerabilities, or selling sensitive information.

## Impact

Successful exfiltration of GitHub repositories can lead to the exposure of sensitive source code, trade secrets, and proprietary algorithms. This can result in significant financial losses, reputational damage, and competitive disadvantage. In the event of secrets exposure (API keys, passwords, etc.), downstream systems and services may also be compromised. Depending on the nature of the exfiltrated code, legal and regulatory repercussions are also possible. Mass cloning of dozens of repositories can quickly siphon proprietary code, embedded secrets, and build artifacts across teams before defenses can respond.

## Recommendation

*   Deploy the Sigma rule `Github Exfiltration via High Number of Clones in Short Time` to your SIEM and tune the threshold (event_count >= 25) for your environment to reduce false positives based on legitimate automated activity.
*   Monitor GitHub audit logs for `git.clone` events, focusing on users with a high number of clones within a short timeframe to catch suspicious activity.
*   Revoke any GitHub tokens identified as being used for mass cloning, and force password resets and 2FA re-verification for the associated user accounts.
*   Investigate the originating host (identified by the `agent.id` or `user_agent` fields) for signs of compromise and block/quarantine it to prevent further exfiltration.
*   Implement organization-wide SAML SSO, disallow classic PATs, and enforce IP allowlisting for PAT use to enhance security posture.
*   Enable secret scanning with push protection on all repositories to prevent accidental or intentional exposure of credentials.
