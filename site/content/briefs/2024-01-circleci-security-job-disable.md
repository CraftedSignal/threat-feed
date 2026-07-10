---
title: CircleCI Security Job Disablement
slug: 2024-01-circleci-security-job-disable
description: An attacker disables mandatory security jobs within CircleCI pipelines to bypass security checks, potentially leading to data breaches, system downtime, and compromised pipeline integrity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - circleci
  - devsecops
  - pipeline-security
  - cloud
vendors:
  - CircleCI
products:
  - CircleCI
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1554
    technique_name: Compromise Infrastructure
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/circle_ci_disable_security_job.yml
rules:
  - title: CircleCI Mandatory Security Job Not Executed
    description: Detects when a mandatory security job is not executed within a CircleCI workflow.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1554
    data_sources:
      - webserver
      - linux
  - title: CircleCI Workflow Configuration Change
    description: Detects modifications to CircleCI workflow configurations that could bypass security checks.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1554
    data_sources:
      - file_event
      - linux
rules_count: 2
---

This threat brief addresses the risk of disabling security jobs within CircleCI pipelines. CircleCI, a popular CI/CD platform, is used by many organizations to automate their software development lifecycle. An attacker who gains sufficient privileges within a CircleCI organization could modify pipeline configurations to disable mandatory security jobs. This allows malicious code to bypass critical security checks, potentially introducing vulnerabilities into production environments. The impact could range from data breaches and system downtime to reputational damage. This brief outlines how detection engineers can proactively identify and respond to such attempts.

## Attack Chain

1.  **Initial Access:** The attacker gains unauthorized access to a CircleCI user account or acquires sufficient permissions to modify pipeline configurations.
2.  **Reconnaissance:** The attacker identifies mandatory security jobs within the CircleCI workflows using the CircleCI UI or API, noting the `workflow_name` and associated `job_name`.
3.  **Configuration Modification:** The attacker modifies the CircleCI pipeline configuration (likely via the `.circleci/config.yml` file) to disable or bypass the identified mandatory security jobs. This might involve commenting out the job definition, removing it from the workflow, or adding conditions that prevent its execution.
4.  **Code Commit:** The attacker commits the modified configuration file to the associated Git repository, triggering a new pipeline execution. The `vcs.url` field provides the URL to the commit and related changes.
5.  **Bypassed Security Checks:** The pipeline executes without running the mandatory security jobs, allowing potentially malicious code to proceed through the CI/CD process unchecked.
6.  **Deployment:** The unchecked code is deployed to staging or production environments.
7.  **Impact:** Depending on the nature of the malicious code, the impact could include data breaches, system compromise, or service disruption.

## Impact

The successful disabling of security jobs in CircleCI can have significant consequences. A single compromised pipeline could lead to the introduction of vulnerable code into production, impacting thousands of users and critical infrastructure. Potential damage includes data breaches, system downtime, reputational damage, and financial loss. Organizations in all sectors utilizing CircleCI for their CI/CD processes are at risk.

## Recommendation

*   Deploy the provided Sigma rule to detect instances where mandatory security jobs are not executed within CircleCI workflows; tune the rule for your environment.
*   Investigate alerts triggered by the Sigma rule, focusing on the `user` and the specific `workflow_name` where the security job was disabled.
*   Review CircleCI access logs for suspicious account activity that might indicate unauthorized access.
*   Implement multi-factor authentication (MFA) for all CircleCI user accounts to reduce the risk of account compromise.
