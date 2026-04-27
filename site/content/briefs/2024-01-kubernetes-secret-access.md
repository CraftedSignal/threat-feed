---
title: Kubernetes Secret Access via Unusual User Agent
slug: 2024-01-kubernetes-secret-access
description: This rule detects when secrets are accessed via an unusual user agent, user name, and source IP in a Kubernetes cluster, indicating potential credential access attempts by attackers seeking sensitive information.
date: "2026-03-26T16:16:30Z"
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
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1552/007/
  - https://attack.mitre.org/tactics/TA0006/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/credential_access_get_secrets_access.toml
rules:
  - title: Kubernetes Secret Accessed from Outside Pod
    description: Detects secret access events originating from outside of a pod within the cluster.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - network_connection
      - kubernetes
  - title: Kubernetes Secret Access via Unusual User Agent
    description: Detects Kubernetes secret access events with unusual user agents.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
      - kubernetes
rules_count: 2
---

This detection rule focuses on identifying unusual access patterns to secrets within a Kubernetes environment. After gaining initial access to a Kubernetes cluster, attackers often target stored secrets to escalate privileges and access sensitive information such as credentials, API keys, and other confidential data. The rule leverages Kubernetes audit logs to monitor API requests for secret retrieval ("get" or "list" actions) and flags instances where the requests originate from an unexpected…
