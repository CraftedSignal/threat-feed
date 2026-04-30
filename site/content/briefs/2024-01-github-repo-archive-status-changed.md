---
title: GitHub Repository Archive Status Changed
slug: 2024-01-github-repo-archive-status-changed
description: Detection of GitHub repository archiving or unarchiving events, which could indicate malicious activity such as persistence, impact, or defense impairment.
date: "2024-01-04T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - github
  - repository
  - archive
  - unarchive
  - persistence
  - impact
  - defense-impairment
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0006
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories
  - https://www.sentinelone.com/blog/exploiting-repos-6-ways-threat-actors-abuse-github-other-devops-platforms
  - https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events
rules:
  - title: GitHub Repository Archive Status Changed
    description: Detects when a GitHub repository is archived or unarchived.
    platform: sigma
    severity: low
    tactics:
      - defense-impairment
      - impact
      - persistence
    data_sources:
      - github
      - audit
  - title: GitHub Repository Archived by User
    description: Detects when a GitHub repository is archived by a specific user.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - impact
      - persistence
    data_sources:
      - github
      - audit
rules_count: 2
---

This threat brief focuses on the detection of unauthorized changes to GitHub repository archive status. Attackers may archive or unarchive repositories as a means of persistence, to impact the availability of resources, or to impair defenses by hiding malicious code. The activity is logged within GitHub's audit logs and can be monitored to identify potentially malicious actions. Monitoring these events can help organizations identify and respond to unauthorized modifications of their GitHub repositories. This is especially relevant for organizations relying heavily on GitHub for code management and collaboration.

## Attack Chain

1. An attacker gains unauthorized access to a GitHub account with repository administration privileges.
2. The attacker authenticates to the GitHub platform using the compromised credentials or a stolen session token.
3. The attacker navigates to the settings page of a target repository.
4. The attacker modifies the repository's archive status, either archiving or unarchiving it depending on their objective.
5. GitHub logs the 'repo.archived' or 'repo.unarchived' action in the organization's audit logs.
6. (If archiving) Legitimate users may lose access to the repository and its code, causing disruption.
7. (If unarchiving) The attacker might reintroduce vulnerable code or malicious content into an active repository.
8. The attacker may then attempt to exploit the unarchived repository for further malicious activities.

## Impact

The impact of unauthorized repository archiving or unarchiving can range from temporary disruption of services to the reintroduction of vulnerable code. A successful attack could lead to data breaches, code compromise, or supply chain attacks. The number of affected repositories depends on the scope of the attacker's access and objectives.

## Recommendation

*   Deploy the Sigma rule "GitHub Repository Archive Status Changed" to your SIEM and tune for your environment. This rule detects the `repo.archived` and `repo.unarchived` actions in GitHub audit logs (logsource: github, service: audit).
*   Review GitHub audit logs regularly for unexpected repository archiving or unarchiving events.
*   Investigate any detected events to determine if the actions were authorized.
