---
title: Detection of GKE API Request Failure Bursts
slug: 2026-09-gke-api-failure-burst
description: This detection identifies anomalous bursts of failed GKE API requests that may indicate credential stuffing, RBAC probing, or reconnaissance activity within Google Kubernetes Engine environments.
date: "2026-09-22T19:17:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - kubernetes
  - gcp
  - discovery
vendors:
  - Google
products:
  - Google Kubernetes Engine
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: Repeated authorization failures across multiple actions can indicate credential stuffing, RBAC probing, or reconnaissance with stolen tokens.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/discovery_gcp_gke_api_request_failure_burst.toml
  - https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
  - https://attack.mitre.org/techniques/T1613/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the GKE API failure burst detection rule to identify potential reconnaissance.
      owner: Detection Engineering
      due: 48h
      evidence: Source documentation for rule 94556bc7-e057-4759-9e49-fa79ee366101
  hunt_leads:
    - lead: Search for instances where failed GKE API requests were followed by successful administrative calls from the same user.
      technique_id: T1613
      data_needed:
        - GCP Audit Logs (k8s.io)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Investigation steps in source documentation suggest hunting for later successful calls indicating privilege escalation.
---

This threat brief addresses the detection of malicious reconnaissance and unauthorized access attempts targeting Google Kubernetes Engine (GKE) clusters. Attackers often perform automated enumeration of cloud resources, RBAC permissions, and container configurations by iterating through API calls using compromised or brute-forced credentials. When these attempts result in a high volume of authorization failures within a short period, they create a detectable pattern of behavior. By monitoring for 10 or more failed GKE API requests from a single user identity within a five-minute window, security teams can identify reconnaissance or credential stuffing campaigns. This detection logic is specifically designed for integration with GCP Fleet logs and helps distinguish between legitimate system activity and potential adversary activity early in the kill chain.

## Impact

Successful exploitation of this behavior could allow an attacker to gain visibility into the cluster architecture, identify high-value targets, or escalate privileges within the GKE environment. If an attacker successfully probes RBAC policies, they may move from unprivileged reconnaissance to full cluster compromise, leading to data exfiltration, container escape, or long-term persistence within the cloud infrastructure.

## Recommendation

Deploy the detection logic to identify unauthorized GKE API activity.

- Enable GCP Fleet integration with GKE audit logging enabled to ensure the required telemetry is available.
- Establish a process for SOC analysts to review `event.action` and `orchestrator.resource.name` fields when alerts trigger to distinguish between legitimate misconfigurations and attacker activity.
- Create an allowlist of known service accounts and CI/CD service identity patterns to reduce noise from legitimate but stale automated tasks.
- Investigate the `source.ip` and `user_agent.original` fields associated with the alert to determine if the activity originates from known organizational ranges or external/suspicious infrastructure.
