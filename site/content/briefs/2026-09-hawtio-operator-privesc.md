---
title: Excessive ClusterRole Permissions in hawtio-operator
slug: 2026-09-hawtio-operator-privesc
description: The hawtio-operator contains an overly permissive ClusterRole configuration that enables an attacker who compromises the operator pod to access all Secrets across the Kubernetes cluster.
date: "2026-09-08T13:40:54Z"
lastmod: "2026-09-08T13:41:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hawtio:hawtio-operator:*:*:*:*:*:*:*:*
tags:
  - oauth
  - privilege-escalation
  - token-harvesting
  - cloud-security
vendors:
  - Hawtio
products:
  - hawtio-operator
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'The operator''s ClusterRole grants secrets: [create, get, list, update, watch] across all namespaces.'
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078.004
    technique_name: 'Valid Accounts: Cloud Accounts'
    evidence: Compromise of the operator pod would yield read access to every Secret in the cluster, including bootstrap tokens, cloud credentials.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: A malicious tenant can register an arbitrary hostname as a valid OAuth redirect target and, because grants are auto-approved, obtain OpenShift access tokens of any cluster user who visits the crafted authorization URL without any consent prompt.
    confidence_band: high
cves:
  - id: CVE-2026-77968
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77968
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80219
action_plan:
  priority: elevated
  owners:
    - SOC
    - DevOps
  immediate_actions:
    - action: Audit RBAC permissions for hawtio-operator ServiceAccount
      owner: DevOps
      due: 48h
      evidence: CVE-2026-77968 description of excessive ClusterRole permissions
  mitigation_plan:
    - priority: immediate
      action: Restrict ClusterRole permissions for hawtio-operator ServiceAccount to specific namespaces
      owner: DevOps
      addresses: CVE-2026-77968
      evidence: NVD vulnerability details regarding operator RBAC flaw
updates:
  - at: "2026-09-08T13:41:01Z"
    level: L2
    summary: added coverage for hawtio-operator
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-80219
---

CVE-2026-77968 describes a security vulnerability in the hawtio-operator involving excessive RBAC permissions. The operator's associated ClusterRole grants the ServiceAccount broad permissions to create, get, list, update, and watch Kubernetes Secrets across all namespaces. Although the operator employs a controller-runtime label-selector cache as a memory optimization, the underlying ServiceAccount token possesses direct, unrestricted access to the Kubernetes API. An attacker who successfully achieves code execution within the hawtio-operator pod can leverage these permissions to bypass cache restrictions via direct API queries, allowing for the unauthorized exfiltration of sensitive information including cloud credentials, service account tokens, and other operator secrets. This flaw significantly expands the impact of a container compromise to a full cluster-wide secret exposure.

## Impact

Successful exploitation of CVE-2026-77968 allows an attacker with pod-level access to escalate privileges to the cluster level by retrieving all stored Secrets. This includes sensitive bootstrap tokens, cloud provider credentials, and secrets belonging to other workloads. Potential consequences include full lateral movement, persistence across the cluster environment, and exfiltration of sensitive data protected by the Kubernetes Secret API.

## Recommendation

1. Audit current Kubernetes RBAC configurations to identify and restrict excessive permissions for the hawtio-operator ServiceAccount.
2. Implement Principle of Least Privilege by constraining ClusterRole permissions to specific namespaces or resources rather than the entire cluster scope, as referenced by CVE-2026-77968.
3. Monitor API server audit logs for anomalous 'list' or 'get' requests on resources of type 'secrets' originating from the hawtio-operator ServiceAccount identity.
