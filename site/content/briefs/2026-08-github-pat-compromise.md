---
title: Coordinated Campaign Exploiting Compromised GitHub Personal Access Tokens
slug: 2026-08-github-pat-compromise
description: A coordinated threat actor leveraged compromised GitHub Personal Access Tokens (PATs) across multiple organizations between May and June 2026 to perform reconnaissance, validate access, and exfiltrate large volumes of proprietary source code.
date: "2026-08-13T16:45:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - credential-theft
  - exfiltration
vendors:
  - GitHub
products:
  - GitHub
  - GitHub Enterprise
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1593
    technique_name: Search Open Technical Databases
    evidence: The threat actor used the GitHub API to query the /repositories/{id}/readme endpoint to collect information regarding accessible repositories.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The cloning operations were performed using valid PATs belonging to employees of the affected organizations.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: The campaign involved mass repository exfiltration across multiple organizations.
    confidence_band: high
references:
  - https://www.wiz.io/blog/investigating-github-pat-compromise
iocs:
  - type: ip
    value: 13.221.167.217
  - type: ip
    value: 107.174.201.183
ioc_counts:
  ip: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review GitHub audit logs for cloning events associated with the known malicious IP addresses.
      owner: SOC
      due: 24h
      evidence: Source provides list of IPs involved in cloning activity.
  hunt_leads:
    - lead: Identify accounts with excessive repository cloning activity across enterprise.
      technique_id: T1537
      data_needed:
        - GitHub audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Mass cloning activity observed on June 1 across multiple victims.
---

Between mid-May and early June 2026, Wiz CIRT identified a coordinated campaign targeting multiple organizations using compromised GitHub Personal Access Tokens (PATs). The attack followed a structured progression: initial repository reconnaissance via the GitHub API, a low-volume validation phase to confirm access, and finally, a massive, automated repository cloning operation. The activity was linked to automated tooling leveraging AWS and HostPapa infrastructure, utilizing distinct user agents for each campaign stage. 

The incident highlights the critical risk of PAT exposure, as unauthorized access to private repositories frequently leads to the exposure of secondary secrets, including cloud credentials and API keys. Organizations are urged to audit GitHub PAT usage and monitor for anomalous cloning activity, specifically originating from non-standard IP ranges or appearing in high-parallelism bursts.

## Attack Chain

1. Attacker obtains valid GitHub PATs through undisclosed means (likely endpoint compromise or credential exposure).
2. Reconnaissance phase (May 15): Attacker queries `/repositories/{id}/readme` endpoint via the GitHub API using an AWS IP (13.221.167.217) and Chrome browser user agent.
3. Validation phase (May 29-31): Attacker uses the compromised PATs to perform small-scale repository cloning from HostPapa infrastructure (107.174.201.183) to verify continued token validity.
4. Exfiltration phase (June 1): Attacker uses 102 AWS IP addresses in the `ca-central-1` region to conduct mass, parallelized repository cloning.
5. Automated tools use `git/2.43.0` user agent for high-concurrency cloning of thousands of repositories.
6. Attacker exfiltrates source code, enabling the identification of further hardcoded secrets within the stolen repositories.
7. Attacker potentially leverages discovered secrets (cloud credentials, API keys) to achieve follow-on compromise in downstream cloud environments.

## Impact

The campaign resulted in the large-scale exfiltration of proprietary source code across multiple organizations. The primary danger of this exfiltration is the subsequent exposure of hardcoded secrets, such as API keys, cloud credentials, and private keys, found within the repositories, which provides the threat actor with a pathway to escalate access into the organizations' broader cloud infrastructure.

## Recommendation

* Review GitHub audit logs for anomalous `git.clone` activity, specifically high volumes of repositories cloned by a single user account within a short timeframe.
* Identify and revoke compromised PATs; enforce SAML SSO for classic PATs and monitor fine-grained PAT usage for unauthorized scope.
* Implement GitHub Enterprise Log Streaming to gain visibility into API-based reconnaissance events that are not captured in standard audit logs.
* Perform an audit of hardcoded secrets in repositories that were accessed during the campaign window to determine if secondary credentials (cloud keys, etc.) were exposed.
* Isolate endpoints associated with the users whose PATs were compromised to check for additional credential theft or malware.
