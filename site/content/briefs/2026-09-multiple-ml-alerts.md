---
title: Correlation of Multiple Machine Learning Alerts by Influencer Field
slug: 2026-09-multiple-ml-alerts
description: This detection rule identifies potential account compromise by correlating three or more distinct machine learning alert triggers associated with the same non-system influencer field.
date: "2026-09-18T19:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - threat-detection
  - machine-learning
  - elastic-security
  - behavioral-analysis
vendors:
  - Elastic
products:
  - Elastic Security
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The detection rule identifies patterns by correlating diverse machine learning alerts linked to the same entity.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Check for any recent changes in user permissions or group memberships that could indicate privilege escalation attempts.
    confidence_band: med
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Look into any recent login attempts or authentication failures for the user account to detect potential brute force or credential stuffing attacks.
    confidence_band: med
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/multiple_machine_learning_jobs_by_entity.toml
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the ESQL detection rule to the production Elastic Security instance.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID da7f7a93-26e1-49ce-b336-963c6dc17c7b
  hunt_leads:
    - lead: Identify users triggering >3 ML jobs in 30 minutes that are not yet flagged by higher-order rules.
      technique_id: T1204
      data_needed:
        - ML job alerts
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Rule logic requires count_distinct_job_id >= 3
---

This brief details a higher-order detection rule developed for the Elastic Security platform, designed to improve the prioritization of machine learning (ML) alerts. By correlating multiple disparate ML jobs that share the same influencer entity (such as a username), the rule identifies clusters of suspicious activity that might otherwise be ignored if triaged in isolation. 

The logic filters out system accounts like "root" or "SYSTEM" to reduce noise and requires a threshold of at least three distinct ML job IDs triggered by the same influencer. This approach helps security operations center (SOC) analysts identify potentially compromised accounts exhibiting a progression of anomalous behaviors across different monitored vectors, such as unusual login patterns, process execution, or file access. This rule is intended to be used as a triage prioritization mechanism rather than a standalone detector of a specific exploit.

## Impact

The failure to identify correlated anomalies from an account can allow attackers to progress through an environment undetected. If an account is compromised, attackers may leverage diverse techniques such as privilege escalation, lateral movement, or data exfiltration. Aggregating these individual anomalous signals into a single high-risk alert enables defenders to isolate compromised entities more rapidly, limiting the potential scope of damage to the organization's network and data.

## Recommendation

Deploy the Elastic Security higher-order rule "Multiple Machine Learning Alerts by Influencer Field" to your production SIEM environment. 

- Review the "Investigation Guide" metadata provided in the source documentation for specific tuning recommendations per environment.
- Implement role-based exceptions for IT administrators and high-volume users in customer support or sales to minimize false-positive fatigue.
- Schedule known maintenance windows and automated update processes as exclusions within the SIEM detection logic to avoid false positives from legitimate background tasks.
- Ensure that telemetry sources for machine learning jobs are correctly configured and ingesting into the .alerts-security index pattern.
