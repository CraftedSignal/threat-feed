---
title: TensorZero Gateway Arbitrary File Read and SSRF Vulnerability
slug: 2026-07-tensorzero-gateway-rce-ssrf
description: A high-severity vulnerability (CVE-2026-54457) in the TensorZero Gateway's `/internal/object_storage` endpoint allows attackers to achieve arbitrary file reading from the gateway filesystem and Server-Side Request Forgery (SSRF) by manipulating the `storage_path` parameter, potentially leading to credential exposure and internal network reconnaissance.
date: "2026-07-15T22:01:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-file-read
  - ssrf
  - web-vulnerability
  - credential-access
  - discovery
  - cloud
  - pip-package
vendors:
  - TensorZero
products:
  - pip/tensorzero (< 2026.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This vulnerability only applies when the gateway can be accessed by untrusted callers.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
    evidence: coerce the gateway into making outbound object storage requests to attacker-chosen internal/cloud-metadata endpoints.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: read arbitrary files from the gateway filesystem, including files that may contain sensitive credentials.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-824w-x939-6cmc
rules:
  - title: Detects CVE-2026-54457 Exploitation - TensorZero Gateway Arbitrary File Read and SSRF
    description: Detects exploitation attempts against CVE-2026-54457 in TensorZero Gateway by identifying HTTP POST requests to `/internal/object_storage` that contain a `storage_path` parameter attempting to use `filesystem` for arbitrary file reads or `s3_compatible` for Server-Side Request Forgery.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1005
      - T1190
      - T1560
      - T1580
    data_sources:
      - webserver
rules_count: 1
---

A high-severity vulnerability, identified as CVE-2026-54457, exists in the TensorZero Gateway's `/internal/object_storage` endpoint, affecting versions prior to 2026.6.0. This flaw allows an attacker to control the `storage_path` parameter by supplying a crafted JSON payload. By abusing the `filesystem` storage type, attackers can read arbitrary files from the gateway's filesystem, potentially exposing sensitive data like credentials. Furthermore, leveraging the `s3_compatible` storage type enables Server-Side Request Forgery (SSRF), coercing the gateway into making outbound requests to attacker-specified internal or cloud-metadata endpoints. This vulnerability is exploitable by untrusted callers if the gateway has authentication disabled, or by authenticated callers if authentication is enabled. Successful exploitation can lead to credential theft, internal network mapping, and exfiltration of cloud resources, posing a significant risk to the affected infrastructure.

## Attack Chain

1. An attacker identifies a TensorZero Gateway instance with an accessible `/internal/object_storage` endpoint.
2. The attacker constructs a malicious JSON payload designed to manipulate the `storage_path` parameter.
3. To achieve arbitrary file reading, the attacker sets the JSON `storage_type` to `filesystem` and specifies a local file path (e.g., `/etc/passwd`).
4. The attacker sends an HTTP POST request to the `/internal/object_storage` endpoint with the crafted JSON payload, potentially URL-encoded, as a parameter or in the request body.
5. The vulnerable TensorZero Gateway processes the request, overriding its object storage configuration and reading the specified local file.
6. The gateway returns the content of the arbitrary file in its response, completing the arbitrary file read.
7. Alternatively, to perform Server-Side Request Forgery (SSRF), the attacker sets the JSON `storage_type` to `s3_compatible` and specifies an internal IP address or a cloud-metadata endpoint URL (e.g., `http://169.254.169.254/latest/meta-data/`).
8. The gateway is coerced into making an outbound request to the attacker-controlled endpoint, returning the response which could contain internal network information or cloud credentials.

## Impact

Successful exploitation of CVE-2026-54457 allows attackers to read arbitrary files from the TensorZero Gateway's filesystem, potentially exposing sensitive configuration files, system credentials, or other confidential data. The Server-Side Request Forgery (SSRF) capability further enables attackers to perform internal network reconnaissance, access internal services, and exfiltrate cloud metadata, such as AWS IAM role credentials, which can lead to broader cloud resource compromise. While the vulnerability requires authentication if enabled, unauthenticated access is possible if the gateway's authentication is disabled, significantly broadening the attack surface. This could lead to a complete compromise of the gateway and further lateral movement within an organization's network or cloud environment. The vulnerability has been patched in version 2026.6.0.

## Recommendation

* Patch CVE-2026-54457 immediately by upgrading TensorZero Gateway to version `2026.6.0` or later to remediate the vulnerability.
* If immediate upgrade is not possible for a gateway exposed to untrusted callers, block external access to the `/internal/object_storage` endpoint at the network perimeter.
* Deploy the provided Sigma rule to detect exploitation attempts against this vulnerability in your web server logs.
* Ensure web server logs are configured to capture full HTTP POST request bodies for the `/internal/object_storage` endpoint to improve detection fidelity against this type of exploitation.
