---
title: Kubernetes Cluster Enumeration via Audit Logs
slug: 2024-01-kubernetes-enumeration
description: Attackers attempt to enumerate and discover sensitive information within a Kubernetes cluster by leveraging common shells, utilities, and specialized tools, as reflected in audit logs.
date: "2024-01-29T12:00:00Z"
severities:
  - medium
tags:
  - kubernetes
  - enumeration
  - cloud
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1609
    technique_name: Container and Resource Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Cloud Account Discovery
references:
  - https://www.nccgroup.com/research/detection-engineering-for-kubernetes-clusters/
  - https://github.com/trufflesecurity/trufflehog
  - https://github.com/corneliusweig/rakkess
rules:
  - title: Kubernetes API Shell Execution via Audit Logs
    description: Detects attempts to execute shells within Kubernetes pods via the audit log, indicating potential enumeration or code execution attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1610
    data_sources:
      - kubernetes
      - audit
  - title: Kubernetes API Tool Usage via Audit Logs
    description: Detects the use of common tools like curl, kubectl, or wget within Kubernetes pods via audit logs.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1105
    data_sources:
      - kubernetes
      - audit
  - title: Kubernetes Reconnaissance Tools via User Agent
    description: Detects reconnaissance activity using tools like Rakkess (access_matrix), TruffleHog, AzureHound, and MicroScanner based on the User-Agent string in Kubernetes audit logs.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595
    data_sources:
      - kubernetes
      - audit
rules_count: 3
---

Attackers are increasingly targeting Kubernetes environments to gain unauthorized access and extract sensitive information. This activity often begins with enumeration and reconnaissance to map out the cluster's configuration, identify potential vulnerabilities, and locate valuable secrets. This involves the use of standard command-line tools and specialized Kubernetes utilities. Audit logs provide a valuable record of these enumeration attempts, particularly API requests containing shell…
