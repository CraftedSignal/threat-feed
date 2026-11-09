---
brief_id: brief-2026-11-09-qubole-cross-account-abuse
event_id: brief-2026-11-09-qubole-cross-account-abuse
revision: 2
activity_at: "2026-11-09T18:36:18Z"
revision_history:
  - revision: 2
    at: "2026-11-09T18:36:18Z"
    checksum: sha256:7b86c2dd55faef5f59e029966203850cc146655549ca0f8b557c8278a62f40fd
    summary: added coverage for Qubole platform
    changed_fields:
      - action_plan
      - iocs
      - lastmod
      - references
      - ttps
      - updates
    source_urls:
      - https://thehackernews.com/2026/11/hackers-exploit-quboles-trusted-aws.html
title: 'Qubole: Unauthorized cross-account IAM role assumption'
slug: 2026-11-qubole-cross-account-abuse
description: A threat actor leveraged compromised IAM credentials from a Qubole AWS account to assume customer integration roles, facilitating wide-scale resource discovery, credential harvesting, and S3 data exfiltration.
date: "2026-11-09T16:09:56Z"
lastmod: "2026-11-09T18:35:25Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
tags:
  - supply-chain-attack
  - cloud-security
  - credential-harvesting
vendors:
  - Amazon
  - Qubole
products:
  - AWS
  - Qubole platform
affected_os:
  - Linux
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078.004
    technique_name: Cloud Accounts
    evidence: The actor used these credentials to assume IAM roles that customers had created to trust Qubole's account.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Once inside multiple victim AWS environments, the threat actor enumerated resources.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: 'The threat actor targeted common places where credentials are stored in AWS: Lambda, Secrets Manager, SSM Parameter Store.'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: Every one succeeded... in some cases downloading entire buckets in a single session.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: It read environment variables for Lambda functions, pulled secrets from Secrets Manager, and read values from the SSM Parameter Store.
    confidence_band: high
references:
  - https://www.wiz.io/blog/qubole-cross-account-access-abused-in-the-wild
  - https://thehackernews.com/2026/11/hackers-exploit-quboles-trusted-aws.html
iocs:
  - type: ip
    value: 45.83.220.211
  - type: ip
    value: 57.129.54.120
  - type: ip
    value: 185.209.199.73
  - type: hash_sha256
    value: 65f061281c9a712e9502793dc4c5035cae490b84da05f7d4223cefa65ad396e4
  - type: ip
    value: 89.37.63.175
ioc_counts:
  hash_sha256: 1
  ip: 4
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Search AWS CloudTrail for AssumeRole events from 805246085872 originating from non-AWS IP space
      owner: SOC
      due: 24h
      evidence: All legitimate platform traffic we observed came from AWS infrastructure.
    - action: Audit CloudTrail logs for Qubole account ID 805246085872 from Oct 1 onward.
      owner: SOC
      due: 24h
      evidence: 'Look for: AssumeRole requests where userIdentity.accountId is 805246085872 and sourceIPAddress is not an AWS address.'
    - action: Rotate all credentials accessible by Qubole-linked IAM roles.
      owner: IT Operations
      due: 48h
      evidence: Rotate all secrets, parameters, and Lambda environment variables that role had access to, and revoke the role active sessions.
  hunt_leads:
    - lead: Identify session names beginning with "quiam-" in AWS CloudTrail AssumeRole events
      technique_id: T1078.004
      data_needed:
        - AWS CloudTrail Management Events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The threat actor used role session names that followed a consistent format of the prefix quiam-.
    - lead: Hunt for AssumeRole sessions beginning with "quiam-"
      technique_id: T1078.004
      data_needed:
        - CloudTrail management events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'Session name: role sessions that start with quiam-, such as quiam-enum.'
    - lead: Identify usage of specific compromised IAM principal IDs AIDA3W7DIFLYOLTK63SFS or AIDAJYRRH5Y3A7AAJM2HW
      technique_id: T1078.004
      data_needed:
        - CloudTrail management events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'IAM principal ID: AIDA3W7DIFLYOLTK63SFS and AIDAJYRRH5Y3A7AAJM2HW.'
  mitigation_plan:
    - priority: immediate
      action: Review and audit IAM cross-account trust policies for Qubole integrations
      owner: IT Operations
      addresses: Unauthorized access to cross-account roles
      evidence: The trust policies were still in place, so the requests succeeded.
    - priority: immediate
      action: Apply source IP or VPC Endpoint restrictions to Qubole IAM trust policies.
      owner: Cloud Security
      addresses: Unauthorized AssumeRole access
      evidence: a source IP condition alone would have blocked every role assumption we observed.
updates:
  - at: "2026-11-09T18:35:25Z"
    level: L1
    summary: added coverage for Qubole platform
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/11/hackers-exploit-quboles-trusted-aws.html
---

Between October 14 and October 26, 2026, a threat actor utilized IAM credentials associated with the Qubole platform (AWS account 805246085872) to perform unauthorized AssumeRole operations in customer AWS environments. The attacker performed reconnaissance, harvested credentials from AWS services (Lambda, Secrets Manager, SSM Parameter Store), and exfiltrated S3 data. Evidence suggests the actor used a malicious ISO image (sso_agent.iso) for potential post-exploitation, and utilized TruffleHog to validate stolen credentials across AWS, Entra ID, and Okta.

## Attack Chain
1. Compromise of IAM credentials (AIDA3W7DIFLYOLTK63SFS or AIDAJYRRH5Y3A7AAJM2HW) within Qubole's AWS account.
2. Initial access via AssumeRole requests to customer integration roles originating from non-AWS infrastructure (Mullvad VPN, OVH VPS).
3. Discovery of environment resources using session names prefixed with "quiam-".
4. Credential harvesting from Lambda environment variables, Secrets Manager, and SSM Parameter Store.
5. Validation of harvested credentials using TruffleHog (e.g., AWS GetCallerIdentity).
6. Exfiltration of S3 bucket contents.
7. Staging of a malicious ISO (sso_agent.iso) on external infrastructure for potential system-level persistence.

## Impact
Confirmed unauthorized access to customer AWS environments, enumeration of cloud configurations, harvesting of secrets and credentials (AWS, Entra ID, Okta), and potential exfiltration of S3 data.

## Recommendation
- Review CloudTrail logs for AssumeRole events where the source identity account is 805246085872 and the source IP originates from outside AWS infrastructure.
- Audit existing cross-account IAM roles for Qubole integrations to ensure they are still required and correctly scoped with specific External IDs.
- Rotate any credentials or secrets identified in environments where Qubole integration roles were active during the period of interest.
- Deploy detection for role session names starting with "quiam-".
