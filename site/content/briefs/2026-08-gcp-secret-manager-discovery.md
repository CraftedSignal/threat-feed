---
title: GCP Secret Manager Cross-Project Secret Enumeration
slug: 2026-08-gcp-secret-manager-discovery
description: This threat brief details the detection of potential reconnaissance activity where an identity performs high-volume ListSecrets calls across multiple Google Cloud projects, a technique used for cloud service discovery.
date: "2026-08-24T21:46:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - gcp
  - reconnaissance
  - discovery
vendors:
  - Google
products:
  - Google Cloud Platform
  - GCP Secret Manager
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
    evidence: Detects a single identity listing Google Cloud Secret Manager secrets across many distinct projects in a short window.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/discovery_gcp_secret_manager_listsecrets_across_multiple_projects.toml
  - https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/list
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable GCP Data Access audit logs for Secret Manager API
      owner: IT Operations
      due: 48h
      evidence: Source requirement for telemetry
    - action: Deploy cross-project Secret Manager list detection
      owner: Detection Engineering
      due: 24h
      evidence: Elastic detection rule logic
  hunt_leads:
    - lead: Identify high-volume Secret Manager ListSecrets activity from unauthorized IPs
      technique_id: T1526
      data_needed:
        - GCP Audit Logs (google.cloud.secretmanager.v1.SecretManagerService.ListSecrets)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source highlights multi-project enumeration as a precursor to credential access
---

This detection brief addresses the risk of reconnaissance within Google Cloud Platform environments, specifically targeting the Secret Manager service. Attackers or unauthorized users may perform mass enumeration of secrets across a GCP organization or folder to map the environment and identify high-value targets. While the `ListSecrets` API method does not return the actual sensitive secret payload, it serves as a critical discovery step. By identifying which projects contain secrets, an adversary can prioritize subsequent `AccessSecretVersion` or `GetSecret` calls to exfiltrate credentials. 

Defenders should look for a single identity or source IP performing `ListSecrets` across 10 or more distinct project IDs in a short lookback interval. This behavior is rarely seen from human users and is typically reserved for automated CSPM tooling, security scanners, or inventory jobs. Distinguishing malicious enumeration from authorized automation requires correlating the identity, source IP, and user-agent string against known enterprise tooling and change management records.

## Impact

Successful reconnaissance via Secret Manager enumeration facilitates targeted attacks against production workloads. If an adversary discovers secrets in specific projects, they may attempt to access sensitive configuration data, database credentials, or API keys, leading to potential data exfiltration or environment-wide compromise. The broad scope of this discovery technique allows attackers to map an entire cloud footprint efficiently.

## Recommendation

* Enable `DATA_READ` audit logging for the Google Cloud Secret Manager API to ensure `ListSecrets` events are captured in the environment's audit logs.
* Deploy detection logic to alert on any principal performing `ListSecrets` across 10 or more distinct GCP projects within a 5-minute interval.
* Establish an allowlist of authorized security scanners, CSPM services, and CI/CD service accounts to reduce noise in the alerting pipeline.
* Audit IAM policies to enforce the principle of least privilege, ensuring human users and service accounts possess only the permissions required for their specific projects rather than broad, cross-project listing capabilities.
* Investigate `event.outcome` fields to identify failed permission probing, which often precedes successful enumeration.
