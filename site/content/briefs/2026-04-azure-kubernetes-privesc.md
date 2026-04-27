---
title: CVE-2026-33105 - Microsoft Azure Kubernetes Service Privilege Escalation
slug: 2026-04-azure-kubernetes-privesc
description: CVE-2026-33105 is a critical vulnerability in Microsoft Azure Kubernetes Service that allows an unauthorized attacker to elevate privileges over a network due to improper authorization.
date: "2026-04-03T00:16:05Z"
severities:
  - critical
tags:
  - azure
  - kubernetes
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-33105
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33105
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33105
ioc_counts:
  email: 2
rules:
  - title: Suspicious Process Connecting to Kubernetes API Server
    description: Detects processes not typically associated with Kubernetes API server access
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - network_connection
      - linux
  - title: Detect Kubernetes API Server Unauthorized Requests
    description: Detects 401 and 403 HTTP responses from the Kubernetes API server, which may indicate exploitation attempts
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-33105, discovered in April 2026, is a critical vulnerability affecting Microsoft Azure Kubernetes Service (AKS). This vulnerability stems from an improper authorization mechanism, allowing an unauthorized attacker to elevate privileges within the network. With a CVSS v3.1 score of 10.0, this flaw represents a severe risk. Successful exploitation could grant attackers complete control over the AKS cluster, potentially impacting all workloads and data managed by the service. Given the…
