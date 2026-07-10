---
title: LMDeploy Vision-Language Module SSRF Vulnerability
slug: 2024-01-lmdeploy-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in LMDeploy's vision-language module, allowing attackers to access cloud metadata services and internal networks by exploiting the lack of URL validation in the `load_image()` function.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lmdeploy
  - ssrf
  - vulnerability
vendors:
  - LMDeploy
products:
  - LMDeploy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-33626
    cvss: 7.5
    epss: 0.4525
references:
  - https://github.com/advisories/GHSA-6w67-hwm5-92mq
iocs:
  - type: ip
    value: 169.254.169.254
  - type: domain
    value: orca.security
  - type: email
    value: igor.stepansky@orca.security
  - type: email
    value: iggy.p0pi@orca.security
ioc_counts:
  domain: 1
  email: 2
  ip: 1
rules:
  - title: Detect LMDeploy SSRF Attempt to Cloud Metadata
    description: Detects attempts to exploit the LMDeploy SSRF vulnerability by accessing cloud metadata endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect LMDeploy SSRF Attempt to Internal IP
    description: Detects attempts to exploit the LMDeploy SSRF vulnerability by accessing internal IP addresses.
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

A Server-Side Request Forgery (SSRF) vulnerability has been identified in the vision-language module of LMDeploy, affecting versions prior to 0.12.3. Specifically, the `load_image()` function in `lmdeploy/vl/utils.py` lacks proper validation of URLs before fetching images. This allows an attacker to craft malicious requests containing URLs pointing to internal resources, cloud metadata endpoints (like AWS's 169.254.169.254), or other sensitive internal network locations. The server, which binds to `0.0.0.0` by default and has API keys disabled, becomes an unwitting proxy, enabling the attacker to potentially steal cloud credentials or access internal services that are not exposed to the internet. This issue was tested against the main branch as of February 4, 2026. Orca Security discovered and reported this vulnerability, designated as CVE-2026-33626.

## Attack Chain

1. An attacker identifies an LMDeploy server running a vulnerable version with vision-language capabilities enabled.
2. The attacker crafts a POST request to the `/v1/chat/completions` endpoint.
3. Within the request body, the attacker includes a malicious `image_url` pointing to an internal resource (e.g., `http://169.254.169.254/latest/meta-data/iam/security-credentials/`).
4. The LMDeploy server receives the request and, without proper validation, passes the `image_url` to the `load_image()` function.
5. The `load_image()` function uses the `requests.get()` method to fetch the resource at the attacker-supplied URL.
6. The server inadvertently retrieves the content from the internal resource (e.g., cloud metadata).
7. The attacker receives the sensitive information (e.g., AWS credentials) through a callback server or other means.
8. The attacker uses the stolen credentials or accessed information to further compromise the system or network.

## Impact

Successful exploitation of this SSRF vulnerability can lead to several critical consequences. Attackers can steal cloud credentials from AWS, Azure, or GCP metadata services, granting them unauthorized access to cloud resources. They can also access internal services and resources that are not exposed to the internet, potentially gaining access to sensitive data or control over internal systems. Furthermore, attackers can use the compromised server as a pivot point to perform port scanning and other reconnaissance activities on the internal network, facilitating lateral movement and further attacks.

## Recommendation

*   Upgrade LMDeploy to version 0.12.3 or later to patch CVE-2026-33626.
*   Implement network segmentation to limit the impact of potential SSRF vulnerabilities.
*   Deploy the Sigma rule "Detect LMDeploy SSRF Attempt to Cloud Metadata" to detect attempts to access cloud metadata endpoints.
*   Monitor network connections from the LMDeploy server for suspicious outbound traffic to internal IP ranges using the "Detect LMDeploy SSRF Attempt to Internal IP" Sigma rule.
