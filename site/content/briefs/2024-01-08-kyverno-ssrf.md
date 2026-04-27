---
title: Kyverno SSRF Vulnerability in CEL HTTP Library
slug: 2024-01-08-kyverno-ssrf
description: A Server-Side Request Forgery (SSRF) vulnerability in Kyverno's CEL HTTP library allows users with namespace-scoped policy creation permissions to make arbitrary HTTP requests, enabling unauthorized access to internal services, cloud metadata endpoints, and data exfiltration.
date: "2026-04-14T22:37:20Z"
severities:
  - high
tags:
  - SSRF
  - kyverno
  - kubernetes
  - cel
  - cloud-security
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2026-4789
    cvss: 9.8
    epss: 0.0002
references:
  - https://github.com/advisories/GHSA-rggm-jjmc-3394
ioc_counts:
  domain: 1
  email: 2
  ip: 1
rules:
  - title: Detect Kyverno NamespacedValidatingPolicy Using http.Get/http.Post
    description: Detects the creation of a NamespacedValidatingPolicy that uses the http.Get or http.Post functions, which could indicate a potential SSRF attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - auditd
      - linux
  - title: Detect Outbound Connections from Kyverno Pods to Metadata Endpoint
    description: Detects network connections originating from Kyverno pods to the cloud metadata endpoint (169.254.169.254), which could indicate SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A Server-Side Request Forgery (SSRF) vulnerability has been identified in Kyverno's CEL HTTP library (`pkg/cel/libs/http/`), affecting versions >= 1.16.0. This flaw allows users with permissions to create namespace-scoped policies to bypass intended restrictions and make arbitrary HTTP requests from the Kyverno admission controller. This can lead to unauthorized access to internal Kubernetes services in other namespaces, cloud metadata endpoints such as 169.254.169.254 (allowing credential…
