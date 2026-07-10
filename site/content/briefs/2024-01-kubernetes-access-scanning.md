---
title: Kubernetes Access Scanning Detection
slug: 2024-01-kubernetes-access-scanning
description: This analytic detects potential reconnaissance activities within a Kubernetes environment by identifying repeated failed access attempts or unusual API requests from unauthenticated users based on Kubernetes audit logs, indicating a potential attacker's preliminary reconnaissance.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - scanning
  - reconnaissance
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Reconnaissance
    technique_id: T1046
    technique_name: Indicator Removal on Host
references:
  - https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
rules:
  - title: Kubernetes Unauthenticated Access Scanning
    description: Detects repeated failed access attempts from unauthenticated users to Kubernetes API server.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1046
    data_sources:
      - webserver
      - linux
  - title: Kubernetes API Server 403 from External IP
    description: Detects repeated 403 errors from external IPs accessing the Kubernetes API server, which may indicate scanning activity
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1046
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

This detection analytic focuses on identifying potential scanning activities targeting Kubernetes environments. It leverages Kubernetes audit logs to detect unauthorized access attempts, probing of public APIs, and potential attempts to exploit known vulnerabilities. The analytic specifically monitors for repeated failed access attempts (HTTP 403 errors) originating from unauthenticated users. The goal is to identify attackers performing preliminary reconnaissance to gather information about the Kubernetes system, which could precede more serious malicious activities. This activity is significant because successful reconnaissance can provide attackers with the information they need to gain unauthorized access to sensitive systems or data within the cluster. The detection logic uses events where "user.groups{}"="system:unauthenticated" and "responseStatus.code"=403, aggregated by source IP to identify hosts exceeding a threshold of failed requests.

## Attack Chain

1.  **Initial Access Attempt:** An attacker attempts to access the Kubernetes API server without proper authentication, potentially using default credentials or exploiting misconfigurations.
2.  **Unauthorized API Request:** The attacker sends a request to a protected API endpoint, resulting in a 403 Forbidden error.
3.  **Reconnaissance Scanning:** The attacker repeats the unauthorized API requests across multiple endpoints or using various techniques to map the Kubernetes environment.
4.  **Audit Log Generation:** Each failed access attempt is logged as an audit event within the Kubernetes audit logs, recording details such as the source IP, requested URI, and response code.
5.  **Log Aggregation and Analysis:** Security monitoring tools, like Splunk, collect and aggregate the Kubernetes audit logs.
6.  **Threshold Trigger:** The analytic detects a source IP exceeding a defined threshold (e.g., 5) of failed access attempts (403 errors) from unauthenticated users within a specific timeframe.
7.  **Alert Generation:** An alert is triggered, indicating potential scanning activity originating from the identified source IP.
8.  **Further Exploitation:** If successful, the attacker leverages the information gathered during the scanning phase to exploit vulnerabilities, escalate privileges, or deploy malicious workloads within the Kubernetes cluster.

## Impact

Successful Kubernetes access scanning allows attackers to map the internal structure of the cluster, identify exposed services, and discover potential vulnerabilities. This reconnaissance phase can lead to unauthorized access to sensitive data, compromise of containerized applications, and lateral movement within the cluster. Depending on the compromised application's function and data access, the attacker could steal secrets, sensitive data, or pivot to other internal systems. The impact can range from data breaches and service disruption to complete control over the Kubernetes cluster.

## Recommendation

*   Enable Kubernetes audit logging to generate the required data source for this detection. Configure the audit policy to capture sufficient detail on API requests, including user identity, request URI, and response status (Kubernetes Audit).
*   Deploy the provided Sigma rules to your SIEM and tune the threshold (`count > 5`) based on your environment's baseline activity and acceptable false positive rate (Sigma Rules).
*   Investigate alerts triggered by the Sigma rules, focusing on the source IP address (`src_ip`) and the specific API requests made to determine the nature and intent of the scanning activity.
*   Block the identified scanning source IP addresses (`sourceIPs{}`) at your network perimeter or within your Kubernetes network policies to prevent further reconnaissance attempts.
*   Review and harden Kubernetes security configurations to minimize the attack surface and prevent unauthorized access to API endpoints (Kubernetes documentation).
