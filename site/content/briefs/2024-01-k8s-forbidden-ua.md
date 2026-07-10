---
title: Kubernetes Forbidden Request from Unusual User Agent
slug: 2024-01-k8s-forbidden-ua
description: Detection of forbidden requests originating from unusual user agents within a Kubernetes environment, potentially indicating adversary attempts to exploit vulnerabilities or evade detection by using non-standard user agents to interact with the Kubernetes API.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - threat-detection
  - execution
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/execution_forbidden_request_from_unsual_user_agent.toml
rules:
  - title: Kubernetes Forbidden Request from Unusual User Agent
    description: Detects forbidden requests originating from unusual user agents in a Kubernetes environment, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - dns_query
      - kubernetes
  - title: Kubernetes Forbidden Request - New User Agent
    description: Detects new user agents making forbidden requests to the Kubernetes API.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - dns_query
      - kubernetes
rules_count: 2
---

This detection rule identifies instances where forbidden requests are made within a Kubernetes environment using unusual user agents. Adversaries may leverage non-standard user agents to interact with the Kubernetes API to blend in with legitimate traffic or evade detection. This activity, coupled with a forbidden request, suggests potential attempts to exploit vulnerabilities or misconfigurations present in the Kubernetes cluster. The rule focuses on identifying deviations from expected user agent patterns to uncover potentially malicious interactions with the Kubernetes API. This matters because successful exploitation could lead to unauthorized access, data breaches, or disruption of services running on the Kubernetes cluster. The rule is based on Kubernetes audit logs.

## Attack Chain

1.  An attacker gains initial access to a system with the ability to send requests to the Kubernetes API.
2.  The attacker crafts a request to the Kubernetes API, potentially targeting a specific resource or endpoint.
3.  The attacker sets a non-standard or unusual user agent in the HTTP request header to attempt to evade detection.
4.  The Kubernetes API server receives the request and evaluates authorization policies.
5.  The request is denied due to insufficient privileges or policy restrictions, resulting in a forbidden request.
6.  The Kubernetes audit logging system records the forbidden request, including the user agent string.
7.  This detection rule analyzes the audit logs, identifying forbidden requests with unusual user agents, excluding those matching known Kubernetes-related user agents.

## Impact

Successful exploitation of Kubernetes vulnerabilities or misconfigurations can lead to significant impact. This includes unauthorized access to sensitive data, such as secrets and configurations, the ability to deploy malicious containers, and potential disruption of critical services running within the cluster. A successful attack could compromise the entire Kubernetes environment, leading to data breaches, service outages, and reputational damage. The exact number of victims and sectors targeted depends on the specific Kubernetes deployment and its associated infrastructure.

## Recommendation

*   Deploy the Sigma rule `Kubernetes Forbidden Request from Unusual User Agent` to your SIEM and tune for your environment.
*   Review the Kubernetes audit logs to identify the source IP address and user associated with the forbidden request to understand its origin and purpose (see the Overview section).
*   Implement stricter access controls and user agent validation to prevent non-standard user agents from interacting with the Kubernetes API unless explicitly allowed (see the Attack Chain section).
*   Enhance monitoring and alerting for similar activities by tuning detection systems to recognize patterns associated with this type of threat, ensuring rapid response to future incidents.
