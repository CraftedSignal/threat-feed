---
title: Chamilo LMS SSRF Vulnerability in Social Wall Feature
slug: 2026-04-chamilo-ssrf
description: A Server-Side Request Forgery (SSRF) vulnerability exists in Chamilo LMS versions prior to 1.11.38 and 2.0.0-RC.3, allowing authenticated attackers to make arbitrary HTTP requests, scan internal ports, and access cloud instance metadata via the Social Wall feature.
date: "2026-04-11T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - chamilo
  - ssrf
  - cve-2026-31941
  - lms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-31941
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31941
rules:
  - title: Detect Chamilo LMS Social Wall SSRF Attempt
    description: Detects attempts to exploit the SSRF vulnerability in the Chamilo LMS Social Wall feature by monitoring for suspicious URLs in the `social_wall_new_msg_main` POST parameter.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1018
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Chamilo LMS Social Wall SSRF Attempt - Alternative
    description: Detects attempts to exploit the SSRF vulnerability in the Chamilo LMS Social Wall feature by monitoring for suspicious URLs in the `social_wall_new_msg_main` POST parameter.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1018
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chamilo LMS, a learning management system, is vulnerable to Server-Side Request Forgery (SSRF) in versions prior to 1.11.38 and 2.0.0-RC.3. This vulnerability resides in the Social Wall feature, specifically the `read_url_with_open_graph` endpoint. By supplying a crafted URL via the `social_wall_new_msg_main` POST parameter, an authenticated attacker can force the Chamilo LMS server to make arbitrary HTTP requests. This SSRF can be leveraged to probe internal services, perform port scanning on the internal network, and potentially access sensitive cloud instance metadata. The vulnerability was patched in versions 1.11.38 and 2.0.0-RC.3. Defenders should prioritize patching and monitoring for suspicious outbound HTTP requests originating from the Chamilo LMS server.

## Attack Chain

1. An attacker authenticates to the Chamilo LMS platform with valid user credentials.
2. The attacker crafts a malicious URL targeting an internal service or resource.
3. The attacker initiates a POST request to the `read_url_with_open_graph` endpoint.
4. The POST request includes the crafted URL within the `social_wall_new_msg_main` parameter.
5. The Chamilo LMS server, without proper validation, processes the POST request.
6. The server then makes an HTTP request to the attacker-supplied URL.
7. If the URL targets an internal service, the attacker may gain unauthorized access or information.
8. Successful exploitation allows the attacker to scan internal ports and potentially access cloud instance metadata, leading to further reconnaissance or lateral movement.

## Impact

Successful exploitation of this SSRF vulnerability could allow an attacker to gain unauthorized access to internal services and data within the organization's network. An attacker could use this vulnerability to enumerate internal systems, gather sensitive information, and potentially escalate privileges within the network. This could also lead to lateral movement, data exfiltration, or other malicious activities. The severity of the impact depends on the sensitivity of the internal services exposed and the attacker's objectives.

## Recommendation

*   Upgrade Chamilo LMS to version 1.11.38 or 2.0.0-RC.3 or later to patch CVE-2026-31941.
*   Implement network segmentation to limit the impact of potential SSRF attacks.
*   Monitor web server logs for POST requests to `/main/social/social_wall/social_wall.ajax.php` with unusual URLs in the `social_wall_new_msg_main` parameter to detect potential exploitation attempts.
*   Deploy the Sigma rule to detect requests with unusual URLs to `social_wall.ajax.php`.
