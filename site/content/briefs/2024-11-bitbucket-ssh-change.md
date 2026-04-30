---
title: Bitbucket Global SSH Settings Changed
slug: 2024-11-bitbucket-ssh-change
description: An attacker modifies Bitbucket global SSH settings to potentially enable unauthorized access and lateral movement.
date: "2024-11-01T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - defense-impairment
  - bitbucket
vendors:
  - Atlassian
products:
  - Bitbucket
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
  - https://confluence.atlassian.com/bitbucketserver/enable-ssh-access-to-git-repositories-776640358.html
rules:
  - title: Bitbucket Global SSH Settings Changed
    description: Detects Bitbucket global SSH access configuration changes.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - lateral-movement
    techniques:
      - T1021.004
    data_sources:
      - bitbucket
      - audit
  - title: Bitbucket SSH Key Added to Global Settings
    description: Detects when an SSH key is added to Bitbucket global settings.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - lateral-movement
    techniques:
      - T1021.004
    data_sources:
      - bitbucket
      - audit
rules_count: 2
---

This brief focuses on the detection of unauthorized changes to Bitbucket's global SSH settings. While the specific actor remains unknown, the modification of these settings is a significant security concern. The activity is detected via Bitbucket audit logs. Modification of global SSH settings can allow attackers to gain unauthorized access to repositories, potentially leading to code compromise, data breaches, or further lateral movement within the network. This activity is particularly important for organizations relying on Bitbucket for source code management and secure development workflows. The audit logs are the primary source of information, specifically focusing on events categorized as 'Global administration' with the action 'SSH settings changed'.

## Attack Chain

1.  The attacker gains initial access to a Bitbucket account with administrative privileges, possibly through credential compromise or exploiting a vulnerability.
2.  The attacker authenticates to the Bitbucket web interface.
3.  The attacker navigates to the global SSH settings configuration page within the Bitbucket administration panel.
4.  The attacker modifies global SSH settings, such as adding a new public key or changing authentication requirements.
5.  Bitbucket logs the 'SSH settings changed' event in the audit logs under the 'Global administration' category.
6.  The attacker leverages the modified SSH settings to clone repositories or push malicious code.
7.  The attacker uses compromised code or data to move laterally within the organization's network, targeting other systems and resources.

## Impact

Successful modification of Bitbucket global SSH settings can allow unauthorized access to all repositories within the Bitbucket instance. This can lead to code theft, injection of malicious code, and data breaches. The impact may extend beyond the Bitbucket environment if the compromised code is deployed to production systems or used in other development processes. Organizations using Bitbucket for critical projects are at higher risk.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect unauthorized changes to Bitbucket global SSH settings in the audit logs.
*   Investigate any detected instances of "SSH settings changed" in the Bitbucket audit logs to determine the legitimacy of the changes.
*   Enforce multi-factor authentication (MFA) for all Bitbucket accounts, especially those with administrative privileges, to mitigate credential compromise as an initial access vector.
*   Review Bitbucket's audit log configuration to ensure the "Advance" log level is enabled to capture the necessary audit events.
