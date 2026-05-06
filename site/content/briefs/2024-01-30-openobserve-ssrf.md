---
title: OpenObserve SSRF via Improper IPv6 Validation
slug: 2024-01-30-openobserve-ssrf
description: OpenObserve versions 0.70.3 and earlier are vulnerable to a server-side request forgery (SSRF) attack due to improper validation of IPv6 addresses in the validate_enrichment_url function, potentially allowing authenticated attackers to access internal services and retrieve sensitive cloud metadata.
date: "2026-04-07T20:16:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - openobserve
  - cloud
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-39361
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39361
rules:
  - title: Detect OpenObserve SSRF Attempt via AWS IMDS Access
    description: Detects network connections from OpenObserve servers to the AWS IMDSv1 endpoint (169.254.169.254), indicating a potential SSRF attempt to steal IAM credentials.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect OpenObserve process making outbound connection
    description: Detects outbound connections from OpenObserve processes, which can be used to detect SSRF.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

OpenObserve, a cloud-native observability platform, contains a server-side request forgery (SSRF) vulnerability (CVE-2026-39361) in versions 0.70.3 and earlier. The vulnerability resides in the `validate_enrichment_url` function within `src/handler/http/request/enrichment_table/mod.rs`. This function fails to properly block IPv6 addresses due to the Rust's `url` crate returning IPv6 addresses with surrounding brackets (e.g., "[::1]") instead of without. This allows an authenticated attacker to bypass intended restrictions and access internal services that are normally blocked from external access. Successful exploitation can lead to the retrieval of sensitive IAM credentials via AWS IMDSv1 (169.254.169.254), GCP metadata, or Azure IMDS on cloud deployments, and probing of internal network services on self-hosted deployments.

## Attack Chain

1. An authenticated attacker identifies the `validate_enrichment_url` function as a potential SSRF target.
2. The attacker crafts a malicious URL containing an IPv6 address with surrounding brackets (e.g., `http://[::1]`).
3. The attacker submits a request to the OpenObserve server, providing the malicious URL to the `validate_enrichment_url` function.
4. The `validate_enrichment_url` function fails to properly validate the IPv6 address due to the brackets.
5. The OpenObserve server initiates a request to the attacker-specified IPv6 address, bypassing intended access restrictions.
6. In a cloud environment, the attacker targets the AWS IMDSv1 endpoint (169.254.169.254) to retrieve IAM credentials.
7. The OpenObserve server retrieves the IAM credentials from the IMDSv1 endpoint and returns them to the attacker.
8. The attacker uses the stolen IAM credentials to gain unauthorized access to cloud resources.

## Impact

Successful exploitation of this SSRF vulnerability can lead to significant consequences, especially in cloud deployments. An attacker can retrieve sensitive IAM credentials from cloud metadata services like AWS IMDSv1 (169.254.169.254), GCP metadata, or Azure IMDS. These stolen credentials can then be used to gain unauthorized access to critical cloud resources, potentially leading to data breaches, service disruption, and financial losses. The vulnerability affects OpenObserve instances version 0.70.3 and earlier. The number of affected organizations is currently unknown, but any organization using a vulnerable version of OpenObserve is at risk.

## Recommendation

*   Upgrade OpenObserve to a version greater than 0.70.3 to patch CVE-2026-39361.
*   Monitor network connections originating from OpenObserve servers to internal IP addresses such as 169.254.169.254 using the provided Sigma rule to detect potential SSRF attempts.
*   Implement network segmentation and access controls to limit the impact of a successful SSRF attack, restricting access from OpenObserve servers to sensitive internal services.
*   Consider disabling IMDSv1 and migrating to IMDSv2 on AWS EC2 instances to mitigate the risk of IAM credential theft.
