---
title: Detection of Bypassed Mandatory Security Jobs in CircleCI Pipelines
slug: 2026-10-circleci-security-job-bypass
description: Detection of unauthorized omission of mandatory security jobs within CircleCI workflows which could indicate an attacker attempting to bypass CI/CD pipeline integrity checks.
date: "2026-10-05T12:05:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ci-cd
  - cloud-security
  - pipeline-integrity
vendors:
  - CircleCI
products:
  - CircleCI
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1554
    technique_name: Compromise Client Software Binary
    evidence: The detection identifies mandatory jobs for each workflow and checks if they were executed; disabling security jobs can allow malicious code to bypass security checks.
    confidence_band: high
rules:
  - title: Detect Omission of Mandatory Security Jobs in CircleCI
    description: Detects instances where mandatory security jobs are missing from a CircleCI workflow execution, indicating a potential bypass of security scanning.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1554
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - DevSecOps
  immediate_actions:
    - action: Deploy CircleCI log monitoring and configure the mandatory job lookup table.
      owner: Detection Engineering
      due: 72h
      evidence: Analytic requires mandatory_job_for_workflow lookup.
  hunt_leads:
    - lead: Identify all workflows currently running in CircleCI that lack recent security scanning job executions.
      technique_id: T1554
      data_needed:
        - CircleCI job execution history
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source describes detecting missing security jobs as a sign of bypassed integrity.
  mitigation_plan:
    - priority: immediate
      action: Enable branch protection and require peer review for all changes to .circleci/config.yml files.
      owner: DevSecOps
      addresses: T1554
      evidence: Preventing unauthorized configuration changes mitigates workflow bypass.
---

This threat brief addresses the risk of unauthorized modifications to CI/CD pipeline configurations in CircleCI, specifically where mandatory security jobs are omitted or disabled. Attackers targeting the software supply chain may attempt to alter pipeline workflows to bypass automated security testing, such as SAST, DAST, or dependency scanning. By disabling these mandatory jobs, malicious code can be introduced into the development lifecycle without triggering alerts or automated blocks. This analytic identifies such anomalies by monitoring CircleCI logs and validating that required security tasks are executed within every workflow. Detecting this activity is critical for maintaining pipeline integrity and preventing the deployment of compromised artifacts.

## Attack Chain

1. An attacker gains access to the version control system or the CI/CD configuration files (e.g., .circleci/config.yml) associated with the project.
2. The attacker modifies the workflow configuration to exclude mandatory security or quality assurance jobs.
3. The attacker pushes the malicious or modified configuration file to the repository.
4. CircleCI detects the new configuration and triggers the CI/CD pipeline.
5. The pipeline executes the modified workflow, skipping the required security scanning tasks.
6. The pipeline completes successfully without performing the necessary security validations.
7. Malicious code is processed through the pipeline, potentially leading to unauthorized execution or compromised software delivery.

## Impact

Successful bypass of security checks in a CI/CD pipeline can lead to the introduction of vulnerabilities or malicious payloads into production environments. This compromise threatens the integrity of the organization's software supply chain, potentially leading to data breaches, system downtime, and severe reputational damage.

## Recommendation

Detection engineering teams should monitor CircleCI logs for workflow execution anomalies. Implement the provided logic to track mandatory security jobs against reported execution logs to identify unauthorized workflow modifications.

- Implement visibility into CircleCI pipeline logs to monitor job execution status.
- Review and maintain a strict list of mandatory security jobs that must run in every project workflow.
- Investigate any pipeline workflow where a mandatory security job is skipped or absent.
- Enforce code signing or branch protection rules in the source control management system to prevent unauthorized modifications to pipeline configuration files.
