---
title: Anomalous Batch Retrieval of AWS Secrets
slug: 2026-10-aws-anomalous-secrets-retrieval
description: Detection of anomalous bulk retrieval of sensitive data from AWS Secrets Manager using the BatchGetSecretValue API, which may indicate unauthorized credential harvesting or account takeover.
date: "2026-10-19T02:50:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloud
  - credential-access
  - t1555.006
vendors:
  - Amazon
products:
  - AWS Secrets Manager
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: The following analytic detects an AWS principal making more than 10 distinct successful Secrets Manager BatchGetSecretValue API calls within one hour.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Review CloudTrail logs for BatchGetSecretValue activity exceeding 10 requests per hour
      owner: SOC
      due: 24h
      evidence: Analytic threshold of 10 requests per hour
  hunt_leads:
    - lead: Identify long-tail BatchGetSecretValue usage by infrequent identities
      technique_id: T1555.006
      data_needed:
        - AWS CloudTrail
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Analytic documentation suggests checking principals that have not used the API in the preceding seven days
  mitigation_plan:
    - priority: medium_term
      action: Enforce least privilege IAM policies for secrets access
      owner: Cloud Security
      addresses: T1555.006
      evidence: Best practice for protecting sensitive secrets
---

This threat brief focuses on the detection of anomalous activity within AWS Secrets Manager, specifically the rapid execution of the `BatchGetSecretValue` API. While this API is designed for efficient retrieval of multiple secrets, an excessive volume of successful requests by a single principal within a short window (defined as more than 10 requests within one hour) often serves as a precursor or evidence of credential harvesting. Attackers who have gained initial access to a cloud environment may attempt to dump credentials, API keys, or database passwords to further their movement, facilitate lateral movement, or achieve persistence. Defenders must distinguish this malicious bulk extraction from legitimate automated processes like credential-rotation services or application initialization scripts to effectively mitigate the risk of account takeover.

## Attack Chain

1. Initial access is gained to an AWS environment, likely through compromised IAM credentials or an insecure EC2 instance profile.
2. The attacker identifies the presence of AWS Secrets Manager within the account infrastructure.
3. The attacker determines the scope of available secrets by enumerating existing secrets.
4. Using the identified identity, the attacker initiates `BatchGetSecretValue` requests to the AWS Secrets Manager service.
5. The attacker executes multiple calls to the API within a one-hour timeframe to bypass standard single-secret request limitations.
6. The exfiltrated sensitive data is used to authenticate to external services, databases, or further internal systems.
7. The attacker uses the harvested secrets to escalate privileges or establish persistence, leading to full account takeover or data exfiltration.

## Impact

Successful exploitation of this technique leads to the unauthorized extraction of highly sensitive information, including database credentials, API keys, and configuration secrets. This exposure frequently results in complete account takeover, significant data exfiltration, or the further compromise of secondary cloud and on-premises resources. The number of impacted secrets can be vast, as `BatchGetSecretValue` enables rapid extraction, limiting the time for defensive intervention.

## Recommendation

Prioritize the investigation of high-volume `BatchGetSecretValue` activity identified by the analytic provided in this brief.

- Enable AWS CloudTrail management event logging and ensure `BatchGetSecretValue` is included in the captured dataset.
- Baseline the activity of known automated systems (e.g., CI/CD pipelines, secret rotators) that legitimately trigger `BatchGetSecretValue` to reduce false positives.
- Investigate all alerts by reviewing the associated `user_arn`, `sourceIPAddress`, and `userAgent` in CloudTrail logs to confirm authorization.
- Implement IAM policies that adhere to the principle of least privilege, restricting access to `secretsmanager:BatchGetSecretValue` only to principals that explicitly require it.
- If a suspicious identity is identified, immediately audit the secret identifiers retrieved and consider rotating the exposed credentials.
