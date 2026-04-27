---
title: Kubernetes Secret Access via Unusual User Agent
slug: 2024-01-09-kubernetes-secret-access
description: Detects unusual access to Kubernetes secrets, potentially indicating an attacker attempting to steal sensitive information after gaining initial access to the cluster.
date: "2026-04-06T12:05:33Z"
severities:
  - low
tags:
  - kubernetes
  - credential-access
  - cloud
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/credential_access_get_secrets_access.toml
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1552/007/
  - https://attack.mitre.org/tactics/TA0006/
rules:
  - title: Kubernetes Secret Access via Unusual User Agent
    description: Detects Kubernetes secret access using uncommon user agents, indicating potential unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552
      - T1552.007
    data_sources:
      - network_connection
      - kubernetes
  - title: Kubernetes Secret Accessed From New Source IP
    description: Detects Kubernetes secret access from a source IP not seen in the last 7 days
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1552
      - T1552.007
    data_sources:
      - network_connection
      - kubernetes
rules_count: 2
---

This detection rule identifies instances where Kubernetes secrets are accessed through atypical means, specifically flagging requests originating from unusual user agents, usernames, or source IPs. The underlying assumption is that after compromising a pod or stealing a kubeconfig file, adversaries often attempt to harvest sensitive information stored as secrets within the Kubernetes cluster. This includes service account tokens, registry credentials, cloud keys, and other critical data. This…
