---
title: High-Risk Repository Activity in DevSecOps Environments
slug: 2026-05-risk-devsecops-repo
description: This analytic identifies high-risk activities within repositories by correlating repository data with risk scores in DevSecOps environments, focusing on scores above 100 and sources with more than three occurrences to highlight potential vulnerabilities leading to data breaches or infrastructure compromise.
date: "2026-05-28T17:45:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - devsecops
  - risk-analysis
  - splunk
vendors:
  - Splunk
  - Amazon
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Amazon Elastic Container Registry
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/risk_rule_for_dev_sec_ops_by_repository.yml
rules:
  - title: Detect High Risk Score Repositories - Splunk
    description: Detects repositories with high risk scores based on Splunk Risk data model.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.003
    data_sources:
      - datamodel
      - splunk
  - title: High Risk DevSecOps Repository Activity - Aggregation Check
    description: Alert when a repository has a high number of risk events and a high aggregate risk score, indicating potential compromise.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.003
    data_sources:
      - datamodel
      - splunk
rules_count: 2
---

This analytic identifies high-risk activities within repositories in DevSecOps environments by correlating repository data with risk scores. It aims to highlight repositories that are frequently targeted by threats, potentially indicating underlying vulnerabilities. The detection leverages findings and intermediate findings created by detections from Dev Sec Ops analytic stories. The search sums risk scores and captures source and user information, focusing on high-risk scores above 100 and sources with more than three occurrences. Identifying these high-risk repositories is crucial, as successful exploitation could lead to significant data breaches or infrastructure compromise. The analytic is designed to work with Splunk Enterprise, Splunk Enterprise Security, and Splunk Cloud.

## Attack Chain

1. An attacker gains initial access to a DevSecOps environment, potentially through compromised credentials or vulnerable code (T1204.003).
2. The attacker interacts with repositories, potentially introducing malicious code or exploiting existing vulnerabilities.
3. Security tools within the DevSecOps pipeline generate risk findings based on the attacker's actions.
4. These risk findings are aggregated and correlated, resulting in increased risk scores for specific repositories.
5. The Splunk analytic identifies repositories with high accumulated risk scores (above 100) and multiple source occurrences (more than 3).
6. Security analysts investigate the flagged repositories to determine the nature of the high-risk activity.
7. If malicious activity is confirmed, incident response procedures are initiated to contain the threat and remediate the vulnerabilities.
8. Successful exploitation of the repository can lead to data breaches, infrastructure compromise, and further lateral movement within the environment.

## Impact

Successful exploitation of identified high-risk repositories can lead to significant data breaches, infrastructure compromise, and disruption of development pipelines. The aggregation of risk scores helps to prioritize investigations, but a failure to identify and remediate these issues promptly can result in widespread damage. The number of affected repositories and the scale of potential data breaches depend on the scope of the attacker's activities and the vulnerabilities present within the targeted repositories.

## Recommendation

*   Enable all relevant detections in the Dev Sec Ops analytic stories within Splunk Enterprise Security to ensure comprehensive risk finding generation, as mentioned in the implementation steps.
*   Deploy the provided correlation search in Splunk to identify high-risk repositories based on accumulated risk scores and source occurrences (search string).
*   Investigate flagged repositories with risk scores exceeding 100 and source counts greater than 3 to validate malicious activity and potential vulnerabilities (search string).
*   Tune the threshold for `source_count` and `sum_risk_score` based on your specific environment and risk tolerance (search string).
*   Utilize the drilldown searches to view detection results and risk events associated with flagged repositories for detailed investigation (drilldown_searches).
