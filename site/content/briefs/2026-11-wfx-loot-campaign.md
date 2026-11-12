---
brief_id: brief-2026-11-12-wfx-loot-campaign
event_id: brief-2026-11-12-wfx-loot-campaign
revision: 1
activity_at: "2026-11-12T14:24:44Z"
title: 'wfx-loot Campaign: Credential Stealing via Compromised GitHub Repository Access'
slug: 2026-11-wfx-loot-campaign
description: The wfx-loot campaign utilized thousands of hijacked developer and bot accounts to inject credential-stealing code into over 1,800 GitHub repositories by abusing CI/CD workflows, shell scripts, and npm installation hooks.
date: "2026-11-12T14:24:44Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.securityweek.com/attacker-targets-60000-github-repositories-in-credential-theft-campaign/
  observed_at: "2026-11-12T08:39:00Z"
  confidence: high
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
tags:
  - credential-theft
  - ci-cd
  - github
vendors:
  - GitHub
  - AWS
  - Azure
products:
  - GitHub Actions
  - npm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The intruder instead relies on valid tokens belonging to developer and bot accounts.
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attacker placed the malware in existing or new GitHub Actions workflows, shell scripts run by CI systems, and npm installation hooks.
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The script looks for GitHub tokens, repository secrets, cloud credentials and AI service keys.
references:
  - https://www.securityweek.com/attacker-targets-60000-github-repositories-in-credential-theft-campaign/
action_plan:
  hunt_leads:
    - lead: Identify anomalies in GitHub Actions workflow execution logs, specifically searching for workflows or shell scripts that contain unexpected 'npm install' hooks or modifications to existing CI/CD pipelines.
      technique_id: T1059
      data_needed:
        - GitHub repository workflow logs
        - CI/CD pipeline configuration audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The attacker placed the malware in existing or new GitHub Actions workflows, shell scripts run by CI systems, and npm installation hooks.
    - lead: Audit authorized GitHub tokens and service account activity to detect irregular access patterns or unusual pull request submissions that deviate from standard developer or bot behavior.
      technique_id: T1078
      data_needed:
        - GitHub organization audit logs
        - Authentication event logs for service accounts
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The intruder instead relies on valid tokens belonging to developer and bot accounts.
    - lead: Monitor process execution and memory access on CI/CD runner instances for scripts searching for environment variables or files matching patterns for 'GitHub tokens', 'repository secrets', 'cloud credentials', or 'AI service keys'.
      technique_id: T1552
      data_needed:
        - CI/CD runner process telemetry
        - Runner memory forensic logs
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: The script looks for GitHub tokens, repository secrets, cloud credentials and AI service keys. It also reads GitHub Actions runner process memory.
---

The wfx-loot campaign, active as of November 10, 2026, utilized thousands of hijacked developer and bot accounts to test access across more than 60,000 GitHub repositories. The attackers injected malicious code into GitHub Actions workflows, shell scripts, and npm installation hooks in repositories where permissions allowed. The script was designed to exfiltrate GitHub tokens, repository secrets, cloud credentials, and AI service keys, while also reading GitHub Actions runner process memory. Attackers typically attempted to conceal activity by reversing code changes and deleting workflow runs.

## Attack Chain
1. Initial Access: Attackers obtained valid access tokens for thousands of developer and bot accounts.
2. Probing: Attackers submitted pull requests across over 61,000 repositories to verify write access.
3. Injection: Malicious code was deployed in repositories where permissions and configuration allowed.
4. Exfiltration: The stealer targeted GitHub tokens, repository secrets, cloud credentials, and AI service keys, with functionality to expand access in AWS and Azure.
5. Evasion: The attacker usually reversed code changes and deleted workflow runs to conceal the activity.

## Impact
The stealer ran in over 1,800 repositories. Organizations have been advised to assume all accessible secrets were compromised if the malware executed.

## Recommendation
Organizations should revoke compromised tokens, rotate exposed secrets, and check for unauthorized cloud changes.
