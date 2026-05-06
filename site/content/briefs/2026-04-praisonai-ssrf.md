---
title: PraisonAI SSRF Vulnerability via Unvalidated api_base Parameter
slug: 2026-04-praisonai-ssrf
description: PraisonAI versions 4.5.89 and earlier are vulnerable to SSRF via the `api_base` parameter in the `passthrough()` function, allowing attackers to make requests to internal services or external hosts, potentially leading to IAM credential theft on cloud infrastructure or access to internal services within the VPC.
date: "2026-04-01T23:22:44Z"
type: advisory
types:
  - advisory
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

PraisonAI versions 4.5.89 and earlier are vulnerable to a Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-34936) due to insufficient validation of the `api_base` parameter within the `passthrough()` function. This flaw allows an attacker to control the base URL used in HTTP requests, enabling them to target internal services, external hosts, or cloud metadata endpoints. The vulnerability arises because the `api_base` parameter is directly concatenated with the `endpoint` parameter and passed to `httpx.Client.request()` without any sanitization. This is triggered in the `passthrough()` function if the `litellm` primary path raises an `AttributeError`. This allows attackers to bypass intended access controls and potentially retrieve sensitive information or trigger unintended actions within the PraisonAI server's network. The vulnerability was reported on April 1, 2026.

## Attack Chain

1. An attacker identifies a PraisonAI instance running a vulnerable version (<= 4.5.89).
2. The attacker crafts a malicious request to the `passthrough()` function, providing a crafted `api_base` parameter.
3. The crafted `api_base` contains the address of an internal service (e.g., Redis, Elasticsearch, Kubernetes API) or the EC2 metadata service (`http://169.254.169.254`).
4. An `AttributeError` is triggered in the `litellm` primary path.
5. The `passthrough()` function, within `passthrough.py`, concatenates the attacker-controlled `api_base` with the specified `endpoint`.
6. The resulting URL is then passed to `httpx.Client.request()`, making an HTTP request to the attacker-specified destination.
7. If targeting the EC2 metadata service, the attacker can retrieve IAM credentials associated with the instance.
8. If targeting internal services, the attacker can potentially access sensitive data or perform unauthorized actions, due to the default `AUTH_ENABLED = False` setting.

## Impact

Successful exploitation of this SSRF vulnerability can lead to serious consequences. On cloud infrastructure, attackers can steal IAM credentials from the EC2 metadata service (IMDSv1), potentially gaining control over the entire AWS account. Internal services within the VPC, such as Redis, Elasticsearch, and Kubernetes API, become accessible without authentication, as the Flask API server deploys with `AUTH_ENABLED = False` by default. This can lead to data breaches, service disruptions, or further lateral movement within the internal network. This vulnerability affects deployments of PraisonAI version 4.5.89 and earlier.

## Recommendation

*   Upgrade PraisonAI to a version greater than 4.5.89 to patch CVE-2026-34936.
*   Implement input validation and sanitization on the `api_base` parameter within the `passthrough()` function to prevent SSRF attacks.
*   If running on AWS, disable IMDSv1 and migrate to IMDSv2 to mitigate the risk of IAM credential theft.
*   Implement network segmentation and access controls to restrict access to internal services from the PraisonAI server.
*   Deploy the following Sigma rule to detect attempts to exploit the SSRF vulnerability by monitoring for connections to the EC2 metadata service or the local loopback address.
