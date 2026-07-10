---
title: Glances IP Plugin SSRF Vulnerability Leading to Credential Leakage
slug: 2024-01-03-glances-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in the Glances IP plugin due to improper validation of the public_api configuration parameter, allowing attackers to force outbound HTTP requests and potentially leak credentials via the Authorization header.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - credential-leakage
  - python
vendors:
  - Glances
products:
  - Glances
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Remote File Copy
references:
  - https://github.com/advisories/GHSA-g5pq-48mj-jvw8
iocs:
  - type: ip
    value: 169.254.169.254
ioc_counts:
  ip: 1
rules:
  - title: Detect Glances Configuration File Modification
    description: Detects modifications to the Glances configuration file, which could indicate an attempt to exploit the SSRF vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - file_event
      - linux
  - title: Detect Outbound Connection to Metadata IP
    description: Detects outbound network connections from the Glances process to cloud metadata IP addresses, potentially indicating SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - network_connection
      - linux
  - title: Detect Public API URL in Glances Configuration
    description: Detects a malicious public API URL in the Glances configuration file
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - file_event
      - linux
rules_count: 3
---

A server-side request forgery (SSRF) vulnerability has been identified in the Glances IP plugin, affecting versions prior to 4.5.4. The vulnerability stems from insufficient validation of the `public_api` configuration parameter. An attacker with the ability to modify the Glances configuration file can exploit this flaw to force the application to make HTTP requests to arbitrary internal or external endpoints. Furthermore, if `public_username` and `public_password` are configured, Glances automatically includes these credentials within the `Authorization: Basic` header of the outbound requests, leading to potential credential leakage to attacker-controlled servers. This issue allows attackers to probe internal network services, retrieve sensitive data from cloud metadata endpoints (e.g., AWS, Azure, GCP), and exfiltrate credentials. The root cause is the direct usage of the `public_api` value within the `urlopen_auth` function without proper validation.

## Attack Chain

1.  Attacker gains access to the Glances configuration file (e.g., through compromised credentials or exposed configuration management).
2.  Attacker modifies the `glances.conf` file, setting `public_api` to a malicious URL, such as `http://127.0.0.1:9999/ssrf-poc` or a cloud metadata endpoint (`http://169.254.169.254/`).
3.  Attacker sets `public_username` and `public_password` in the `glances.conf` file to capture the Basic Authentication header.
4.  The Glances application, particularly the IP plugin, reads the modified configuration file during startup or refresh.
5.  The `ThreadPublicIpAddress` class initiates an HTTP request to the attacker-controlled URL using the `urlopen_auth` function in `glances/globals.py`.
6.  The `urlopen_auth` function sends the request with the `Authorization: Basic` header containing the configured username and password, to the attacker controlled endpoint.
7.  The attacker's server receives the request, captures the leaked credentials from the Authorization header, and potentially uses them for further exploitation.
8.  The Glances API endpoint `/api/4/ip` reflects the attacker-controlled data, potentially injecting arbitrary information into the application.

## Impact

Successful exploitation of this SSRF vulnerability can have several serious consequences. Attackers can gain unauthorized access to internal network services and sensitive data residing on the local machine or within the internal network. Credential leakage, due to the inclusion of usernames and passwords in the Authorization header, can lead to further compromise of other systems and services. Cloud metadata endpoints can be queried to obtain sensitive credentials for cloud environments (AWS, Azure, GCP). Furthermore, by manipulating the response received from the attacker-controlled server, arbitrary data can be injected into the Glances application, potentially leading to further exploitation or disruption of services.

## Recommendation

*   Deploy the following Sigma rule to detect modifications to the Glances configuration file to identify potential exploitation attempts.
*   Apply input validation to the `public_api` configuration parameter within the Glances IP plugin to enforce scheme restrictions (http/https only) and validate the destination host, mitigating SSRF vulnerabilities as detailed in the overview.
*   Implement network segmentation to limit the impact of successful SSRF attacks by restricting access to internal resources from the Glances server.
*   Monitor network connections originating from the Glances server for suspicious outbound traffic to internal or cloud metadata IP ranges.
