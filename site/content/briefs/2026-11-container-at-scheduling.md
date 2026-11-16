---
brief_id: brief-2026-11-16-container-at-scheduling
event_id: brief-2026-11-16-container-at-scheduling
revision: 1
activity_at: "2026-11-16T10:21:33Z"
title: Linux Container Scheduled Job Creation via At Utility
slug: 2026-11-container-at-scheduling
description: The use of 'at' or 'atd' job-scheduling utilities within Linux containers is typically anomalous and often signals adversary activity attempting to establish persistence or defer command execution following a compromise.
date: "2026-11-16T10:21:33Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Detection logic defined via product-native telemetry.
tags:
  - container-security
  - persistence
  - execution
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
    subtechnique_id: T1053.002
    subtechnique_name: At
    evidence: Adversaries abuse "at" to establish persistence or to execute a payload at a later time after gaining a foothold inside a container.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    subtechnique_id: T1053.002
    subtechnique_name: At
    evidence: Adversaries abuse "at" to establish persistence or to execute a payload at a later time after gaining a foothold inside a container.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/execution_at_scheduled_job_inside_a_container.toml
  - https://attack.mitre.org/techniques/T1053/002/
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
    - SOC
  hunt_leads:
    - lead: Identify execution of 'at' or 'atd' within container environments using container process-creation logs.
      technique_id: T1053.002
      data_needed:
        - Container ID
        - Process Name
        - Process Arguments
        - Parent Process Name
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: This rule detects execution of the "at" or "atd" job-scheduling utilities inside a Linux container.
  mitigation_plan:
    - priority: short_term
      action: Baseline container images to identify legitimate uses of 'at' and exclude them from alerting to reduce false positives.
      owner: Detection Engineering
      addresses: T1053.002
      evidence: Some container images bundle the "at"/"atd" utilities and a small number of workloads may legitimately schedule one-time jobs.
---

## Overview

Adversaries may abuse the 'at' or 'atd' job-scheduling utilities to establish persistence or defer the execution of malicious payloads after gaining a foothold inside a Linux container. Because containers are intended to be immutable, single-purpose, and managed via external orchestration (such as Kubernetes CronJobs), the presence of in-container scheduling is highly atypical.

## Impact

Compromised containers may be used to maintain access or delay execution of follow-on tasks, potentially evading immediate detection by performing actions asynchronously or at a later time.

## Recommendation

- Deploy detection for 'at' or 'atd' process execution within container environments using container-aware security tooling.
- Investigate alerted containers for signs of prior malicious activity, such as shell access, package installation, or lateral movement attempts.
- Baseline container images and orchestrator namespaces to identify and exclude legitimate administrative workloads that may require job scheduling.
- Isolate containers where unauthorized scheduling is identified, remove the queued jobs using 'at -r', and investigate the compromised workload for remediation.
