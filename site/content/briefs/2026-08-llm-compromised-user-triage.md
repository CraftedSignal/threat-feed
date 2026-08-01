---
title: Automated LLM-Based User Account Compromise Triage
slug: 2026-08-llm-compromised-user-triage
description: An automated detection framework that uses Large Language Models to correlate disparate security alerts and assess potential account compromise based on behavioral indicators.
date: "2026-08-01T01:42:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - identity-compromise
  - llm-security
  - detection-engineering
  - automated-triage
vendors:
  - Elastic
products:
  - Elastic Stack (9.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The rule assesses patterns indicative of credential theft or unauthorized access.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: The rule triggers on alert patterns that suggest credential theft or unauthorized access.
    confidence_band: med
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: The rule evaluates alert patterns for multi-host activity suggesting lateral movement.
    confidence_band: high
references:
  - https://www.elastic.co/docs/reference/query-languages/esql/esql-commands#esql-completion
  - https://www.elastic.co/security-labs/elastic-advances-llm-security
---

This detection capability, introduced for the Elastic Stack (version 9.3.0+), implements an automated triage mechanism using Large Language Models (LLM) to identify compromised user accounts. The rule functions as a higher-order detection, aggregating existing security alerts within a 30-minute window to look for patterns indicative of credential theft or unauthorized access. By analyzing cross-host activity, MITRE ATT&CK tactic progression, and source anomalies, the integrated LLM generates a confidence score and a verdict for each user. This automated analysis assists SOC analysts in filtering through high volumes of signal, specifically highlighting cases where multiple rules have triggered against a single user across different data sources, such as endpoint authentication logs or cloud provider activity.

## Attack Chain

1. Initial access via credential theft or phishing against a specific user entity.
2. The attacker triggers multiple low-to-medium fidelity security rules across the network.
3. The compromised user account performs activity across multiple hosts (lateral movement).
4. Disparate security signals are generated in the SIEM, including credential access or unusual file modifications.
5. The LLM-based triage rule aggregates these signals by unique user ID and username.
6. The LLM evaluates the aggregated alert context for malicious patterns (e.g., initial access to lateral movement).
7. The rule filters and surfaces high-confidence (score > 0.7) indicators of account compromise for analyst review.
8. SOC teams initiate response actions such as account suspension or MFA reset based on the LLM verdict.

## Impact

Successful account compromise often leads to unauthorized data access, lateral movement within the environment, and potential exfiltration. By automating the triage of these multi-faceted attacks, the rule reduces the time-to-detect and prevents attackers from lingering within a compromised account by surfacing hidden correlations that human analysts might miss in a high-alert-volume environment.

## Recommendation

- Deploy the ES|QL triage rule on Elastic Stack 9.3.0 or later to automate the identification of compromised credentials.
- Configure the LLM connector in the Elastic Stack to utilize a trusted provider such as Azure OpenAI, Amazon Bedrock, or the native managed LLM v2 if using Elastic Cloud.
- Prioritize investigations where the LLM verdict is 'TP' (True Positive) and the confidence score exceeds 0.9.
- Conduct regular audits of users identified by this rule to verify legitimacy and prevent drift in credential access patterns.
