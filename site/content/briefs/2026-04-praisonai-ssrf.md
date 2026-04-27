---
title: PraisonAI SSRF Vulnerability via Unvalidated api_base Parameter
slug: 2026-04-praisonai-ssrf
description: PraisonAI versions 4.5.89 and earlier are vulnerable to SSRF via the `api_base` parameter in the `passthrough()` function, allowing attackers to make requests to internal services or external hosts, potentially leading to IAM credential theft on cloud infrastructure or access to internal services within the VPC.
date: "2026-04-01T23:22:44Z"
severities:
  - high
tags:
  - ssrf
  - praisonai
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-x6m9-gxvr-7jpv
ioc_counts:
  ip: 1
rules:
  - title: Detect PraisonAI SSRF Attempt via api_base to Metadata Service
    description: Detects attempts to exploit the PraisonAI SSRF vulnerability by monitoring for connections to the EC2 metadata service IP address in the api_base parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PraisonAI SSRF Attempt via api_base to Loopback Address
    description: Detects attempts to exploit the PraisonAI SSRF vulnerability by monitoring for connections to the local loopback address in the api_base parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PraisonAI versions 4.5.89 and earlier are vulnerable to a Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-34936) due to insufficient validation of the `api_base` parameter within the `passthrough()` function. This flaw allows an attacker to control the base URL used in HTTP requests, enabling them to target internal services, external hosts, or cloud metadata endpoints. The vulnerability arises because the `api_base` parameter is directly concatenated with the `endpoint` parameter…
