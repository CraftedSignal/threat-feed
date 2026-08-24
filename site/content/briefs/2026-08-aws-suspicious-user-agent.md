---
title: Detection of Suspicious AWS API Activity via Offensive Tooling User Agents
slug: 2026-08-aws-suspicious-user-agent
description: This brief details the detection of successful AWS API calls utilizing user-agent fingerprints associated with Kali Linux or TruffleHog, which are commonly indicative of credential testing or unauthorized access attempts.
date: "2026-08-24T09:50:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloud
  - initial-access
  - defense-evasion
vendors:
  - Amazon
products:
  - AWS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The rule identifies successful AWS API calls where the CloudTrail user agent indicates offensive tooling.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The activity may indicate compromised credentials, unauthorized access, or security tooling operating outside approved scope.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
  - https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/
  - https://trufflesecurity.com/blog/trufflehog-in-your-logs
  - https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise
rules:
  - title: AWS Suspicious User Agent Fingerprint
    description: Detects successful AWS API calls using user agents associated with Kali Linux or TruffleHog, indicating potential credential validation or unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - webserver
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
  immediate_actions:
    - action: Review CloudTrail logs for the flagged indicators and verify the IAM principal intent.
      owner: SOC
      due: 24h
      evidence: Detection logic identifies anomalous usage of offensive tooling in cloud environments.
  hunt_leads:
    - lead: Search for non-standard user agent strings in CloudTrail logs originating from unusual source IPs.
      technique_id: T1078
      data_needed:
        - user_agent.original
        - source.ip
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Rule targets common offensive tool fingerprints.
  mitigation_plan:
    - priority: short_term
      action: Enforce MFA and source IP restrictions on high-privileged IAM roles.
      owner: IT Operations
      addresses: T1078.004
      evidence: Standard security practice to mitigate credential abuse.
---

Security teams should monitor for unauthorized use of AWS API credentials by identifying suspicious user-agent strings within CloudTrail logs. Attackers frequently use Kali Linux to interact with AWS environments, leaving `distrib#kali` fingerprints, or leverage tools like TruffleHog to validate stolen credentials against cloud APIs. These activities are highly indicative of compromised IAM principals or unauthorized external scanning. While these tools may exist within authorized penetration testing or DevSecOps workflows, their usage outside of documented change windows or by unexpected IAM roles often signals an active security incident. This detection mechanism specifically targets successful API calls to distinguish between noise and high-confidence alerts.

## Attack Chain

1. Attacker obtains valid AWS IAM access keys or temporary security tokens through phishing, secret leakage, or source-code repository compromise.
2. Attacker configures a CLI/SDK environment, potentially using a Kali Linux distribution for its pre-installed toolset.
3. Attacker uses a tool such as TruffleHog to programmatically verify the validity and scope of the stolen credentials by making authenticated AWS API calls.
4. Attacker performs discovery tasks, such as `ListRoles`, `GetCallerIdentity`, or `ListBuckets`, to assess the permissions attached to the compromised account.
5. Attacker executes higher-impact API actions, such as `CreateAccessKey` for persistent access or `AssumeRole` to escalate privileges across accounts.
6. Attacker exfiltrates sensitive data or modifies infrastructure configurations to establish long-term persistence.

## Impact

Successful exploitation allows threat actors to gain unauthorized access to cloud environments, leading to potential data exfiltration, service disruption, or infrastructure manipulation. The use of automated tools allows for rapid discovery and privilege expansion, potentially exposing an entire organization's cloud footprint if high-privileged keys are compromised.

## Recommendation

- Deploy the provided Sigma rule to alert on non-standard user agents in your SIEM environment.
- Implement service control policies (SCPs) or IAM policies to restrict API access for sensitive roles to known corporate IP ranges or VPN gateways.
- Establish a process to audit and rotate access keys for any IAM principal flagged by these user-agent signatures.
- Review all authorized red team or automated security scanning activities to ensure they are properly documented and allowlisted to reduce alert fatigue.
