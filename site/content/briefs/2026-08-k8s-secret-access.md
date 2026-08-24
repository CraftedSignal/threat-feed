---
title: Kubernetes Secret Access by Node or Pod Identities
slug: 2026-08-k8s-secret-access
description: Attackers are exploiting compromised pod service accounts and node identities to perform unauthorized 'get' or 'list' operations on the Kubernetes Secrets API to harvest sensitive credentials.
date: "2026-08-24T15:47:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - kubernetes
  - cloud
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers who stole a pod service-account token or node credentials sweep Secret objects for tokens, registry credentials, TLS keys, or application configuration.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/credential_access_kubernetes_secret_read_by_node_or_pod_service_account.toml
  - https://attack.mitre.org/techniques/T1552/007/
  - https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens
rules:
  - title: Detect Unauthorized Kubernetes Secret Read
    description: Detects potential credential access by monitoring kubelet or pod service account identities performing 'get' or 'list' operations on the Secrets API resource.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rules for unauthorized secret reads.
      owner: Detection Engineering
      due: 48h
      evidence: Source detection logic.
  mitigation_plan:
    - priority: short_term
      action: Review and restrict RBAC permissions for pod service accounts and nodes.
      owner: IT Operations
      addresses: T1552.007
      evidence: Security recommendation in source.
---

Kubernetes environments face significant risk from credential access techniques where compromised pod service accounts or node identities (kubelet) are used to query the Kubernetes API for sensitive secrets. Because these identities are meant to operate with predictable, limited API access, direct enumeration of 'Secrets' objects is highly anomalous. Attackers utilize these stolen tokens or node credentials to sweep the cluster for registry credentials, TLS certificates, private keys, and application configuration. This behavior is particularly dangerous as it enables lateral movement and privilege escalation. While some legitimate in-cluster controllers perform these actions, unauthorized use by service accounts or nodes - especially those originating from non-local IP addresses - indicates malicious intent to access protected material. Defensive teams must monitor Kubernetes API server audit logs to detect these unauthorized read operations.

## Impact

Successful exploitation allows attackers to bypass security boundaries and exfiltrate sensitive data stored within Kubernetes Secrets. This can lead to full cluster compromise, unauthorized access to external services through exposed registry credentials, and the potential for persistent backdoors. The scope of impact includes any workload, infrastructure component, or secret managed within the cluster namespace.

## Recommendation

* Deploy the Sigma rules provided in this brief to detect unauthorized 'get' or 'list' requests on the Secrets API from nodes and service accounts.
* Establish a baseline for legitimate service account activity to identify anomalous user agents, namespace access, or resource requests.
* Implement least-privilege RBAC policies, ensuring that service accounts and node identities only have access to the specific secrets required for their function.
* Monitor Kubernetes audit logs for `authorization_k8s_io/decision` field values that indicate denied access attempts, as these serve as early warning signs of discovery activity.
* Rotate credentials and revoke tokens immediately upon detecting unauthorized secret enumeration.
