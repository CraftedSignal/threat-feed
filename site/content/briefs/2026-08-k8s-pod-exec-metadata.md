---
title: Kubernetes Pod Exec Exploitation of Cloud Instance Metadata
slug: 2026-08-k8s-pod-exec-metadata
description: Threat actors utilize Kubernetes pod exec sessions to query cloud instance metadata endpoints for credential harvesting and unauthorized access to cloud environment resources.
date: "2026-08-24T15:47:03Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Amazon
  - Google
  - Microsoft
products:
  - AWS IMDS
  - GCP Metadata Server
  - Azure Instance Metadata Service
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Adversaries may leverage Kubernetes pod exec sessions to interact with cloud instance metadata endpoints to harvest temporary security credentials.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
    evidence: Detects Kubernetes pod exec sessions whose decoded command line references cloud instance metadata endpoints.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1552/005/
  - https://hardenedsecurity.io/blog/aws-imds-vulnerabilities-and-mitigations/
iocs:
  - type: ip
    value: 169.254.169.254
  - type: domain
    value: metadata.google.internal
ioc_counts:
  domain: 1
  ip: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit Kubernetes API server logs for 'exec' operations involving metadata-related URLs.
      owner: SOC
      due: 24h
      evidence: Rule ID a8e7d6c5-b4a3-2918-0f9e-8d7c6b5a4032
  mitigation_plan:
    - priority: immediate
      action: Apply network policies to block egress to 169.254.169.254 from all non-privileged pods.
      owner: IT Operations
      addresses: T1552.005
      evidence: Source documentation on mitigations for cloud metadata access
---

Unauthorized access to cloud instance metadata services via Kubernetes (K8s) containers is a significant security risk in multi-tenant and regulated environments. Adversaries who gain access to a K8s cluster and successfully perform a pod exec operation can abuse this capability to interact with link-local IP addresses (e.g., 169.254.169.254) or cloud-provider specific hostnames. By targeting AWS IMDS, GCP computeMetadata, or Azure IMDS, attackers can exfiltrate sensitive data, including temporary IAM role credentials, OAuth tokens, and instance metadata. This technique allows an attacker to pivot from a compromised container to the underlying node identity, potentially leading to widespread privilege escalation across the cloud environment. Defenders must monitor Kubernetes API audit logs for suspicious exec request patterns that include metadata-related strings.

## Attack Chain

1. Attacker gains initial access to the Kubernetes cluster through an exploited service or compromised pod.
2. Attacker identifies a high-value pod that has access to the cloud environment or elevated IAM permissions.
3. Attacker uses the `kubectl exec` API to execute commands within the context of the targeted container.
4. Attacker crafts a command-line string (e.g., `curl` or `wget`) pointing to cloud provider metadata endpoints.
5. The containerized process transmits an HTTP request to the metadata service (e.g., 169.254.169.254) from within the K8s pod network.
6. The metadata service returns temporary credentials, tokens, or instance attributes to the container.
7. Attacker captures and exfiltrates the returned credentials to a remote command-and-control server.
8. Attacker uses the stolen credentials to authenticate to cloud APIs and achieve unauthorized data access or persistence.

## Impact

Successful exploitation allows attackers to bypass container isolation and assume the identity of the underlying cloud instance profile. This typically leads to full credential compromise for the associated IAM role, facilitating lateral movement into cloud infrastructure, data exfiltration from storage buckets, or the modification of infrastructure settings within AWS, GCP, or Azure environments.

## Recommendation

- Implement network policies that strictly deny pod access to the cloud metadata service IP (169.254.169.254) and other internal cloud service hostnames.
- Audit all uses of `kubectl exec` within the cluster to baseline administrative behavior and identify anomalous requests.
- Enable Kubernetes API server audit logging and ingest these logs into a SIEM for detection and correlation.
- Review IAM roles associated with K8s nodes and minimize the scope of permissions to follow the principle of least privilege.
- Deploy detection logic focused on command-line arguments within audit logs that reference metadata service paths, as provided in the detection section below.
