---
title: Kubernetes Unauthorized Access Attempt Detection
slug: 2024-01-kubernetes-unauth-access
description: This analytic detects unauthorized access attempts to Kubernetes by analyzing Kubernetes audit logs, identifying anomalies in access patterns based on request source and response statuses, potentially leading to unauthorized control over Kubernetes resources.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - unauthorized_access
  - cloud
vendors:
  - Kubernetes
  - AWS
products:
  - Kubernetes
  - Amazon Elastic Kubernetes Service (EKS)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
references:
  - https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
  - https://github.com/signalfx/splunk-otel-collector-chart/blob/main/docs/migration-from-sck.md
  - https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
  - https://splunk.github.io/splunk-add-on-for-amazon-web-services/CloudWatchLogs/
rules:
  - title: Kubernetes Unauthorized Access
    description: Detects unauthorized access attempts to Kubernetes based on audit logs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - webserver
      - linux
  - title: Kubernetes Excessive Forbidden Responses
    description: Detects excessive Forbidden responses from a single source IP, indicating potential brute-force access attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This detection identifies unauthorized access attempts to Kubernetes environments by scrutinizing Kubernetes audit logs. The analysis focuses on identifying anomalies in access patterns, specifically examining the source IPs of requests and their corresponding response statuses. Given the critical role of Kubernetes in orchestrating containerized applications, unauthorized access attempts are a significant security concern, potentially indicating an attacker's attempt to infiltrate the cluster. Successful infiltration could lead to unauthorized control over Kubernetes resources, potentially compromising sensitive systems or data within the cluster. This detection leverages Kubernetes audit logs and requires proper configuration of audit policies and log collection mechanisms.

## Attack Chain

1.  The attacker attempts to access the Kubernetes API server without proper authentication.
2.  The Kubernetes API server evaluates the request based on configured RBAC policies.
3.  Due to insufficient permissions or misconfiguration, the API server returns a "Forbidden" (403) response code.
4.  The Kubernetes audit logging system records the unauthorized attempt, including the source IP, username, and requested resource.
5.  The security monitoring system ingests the Kubernetes audit logs.
6.  The detection logic analyzes the logs for "Forbidden" response statuses related to resource creation attempts (verb=create).
7.  Statistical analysis identifies anomalies in access patterns.
8.  If the number of "Forbidden" events from a specific source IP or user exceeds a threshold, an alert is triggered, indicating a potential unauthorized access attempt.

## Impact

Successful unauthorized access to a Kubernetes cluster can have severe consequences. An attacker can gain control over cluster resources, potentially leading to the deployment of malicious containers, data exfiltration, or denial-of-service attacks. The impact could range from compromised applications and data to complete cluster takeover, affecting all workloads running within the environment. Kubernetes clusters often manage sensitive data and critical applications, making them prime targets for attackers.

## Recommendation

*   Enable Kubernetes audit logging to capture API server requests and responses as described in the "how_to_implement" section of the source material.
*   Deploy the Sigma rule `Kubernetes Unauthorized Access` to your SIEM and tune the threshold based on your environment's baseline activity to reduce false positives.
*   Configure the Splunk OpenTelemetry Collector for Kubernetes to collect audit logs, as detailed in the "how_to_implement" section of the source.
*   Investigate triggered alerts by examining the source IP, username, and requested resource from the `kube_audit` logs to determine the nature and intent of the unauthorized access attempt.
*   Enrich alerts with context from other security tools and threat intelligence feeds to identify known malicious actors or infrastructure.
*   Implement and regularly review RBAC policies to ensure least privilege access and prevent unauthorized resource creation.
