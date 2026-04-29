---
title: Chamilo LMS Unauthenticated SSRF Vulnerability
slug: 2026-04-chamilo-ssrf
description: An unauthenticated server-side request forgery (SSRF) vulnerability exists in Chamilo LMS versions prior to 2.0.0-RC.3, allowing attackers to probe internal network services, access cloud metadata, or trigger state-changing operations on internal services.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - chamilo
  - ssrf
  - cve-2026-34160
  - lms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34160
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34160
iocs:
  - type: ip
    value: 169.254.169.254
ioc_counts:
  ip: 1
rules:
  - title: Detect Chamilo LMS SSRF Attempt via Package URL
    description: Detects potential SSRF attempts in Chamilo LMS by monitoring the package-url parameter for suspicious values like internal IP addresses or cloud metadata endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Chamilo LMS PENS Plugin Access
    description: Detects access to the Chamilo LMS PENS plugin endpoint. This rule can be used in conjunction with other rules to identify potential SSRF exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chamilo LMS, an open-source learning management system, is vulnerable to a Server-Side Request Forgery (SSRF) flaw in versions prior to 2.0.0-RC.3. The vulnerability resides within the PENS plugin endpoint at `public/plugin/Pens/pens.php`, which is accessible without authentication. The `package-url` parameter is not properly validated, allowing an attacker to specify arbitrary URLs for the server to fetch using curl. This enables unauthenticated attackers to probe internal network services, access cloud metadata endpoints like `169.254.169.254` to potentially steal IAM credentials, and trigger state-changing operations on internal services via callback parameters. The absence of authentication requirements significantly broadens the attack surface. The vulnerability is identified as CVE-2026-34160 and has been fixed in version 2.0.0-RC.3.

## Attack Chain

1.  Attacker identifies a Chamilo LMS instance running a vulnerable version (prior to 2.0.0-RC.3).
2.  Attacker crafts a malicious HTTP request targeting the `public/plugin/Pens/pens.php` endpoint.
3.  The request includes the `package-url` parameter, set to an internal IP address or cloud metadata endpoint (e.g., `169.254.169.254`).
4.  The Chamilo server, using curl, fetches the URL specified in the `package-url` parameter without proper validation.
5.  If targeting an internal service, the attacker probes for open ports and accessible services.
6.  If targeting a cloud metadata endpoint, the attacker retrieves sensitive information like IAM roles and instance metadata.
7.  The attacker uses the retrieved IAM credentials to access other cloud resources.
8.  Alternatively, the attacker manipulates receipt and alerts callback parameters to trigger state-changing operations on internal services.

## Impact

Successful exploitation of this SSRF vulnerability allows attackers to gain unauthorized access to internal network resources and sensitive cloud metadata. This can lead to lateral movement within the internal network, data exfiltration of IAM credentials, or compromise of cloud infrastructure. The vulnerability affects all Chamilo LMS instances running versions prior to 2.0.0-RC.3. The impact can range from information disclosure to full compromise of the affected system and associated cloud resources.

## Recommendation

*   Upgrade Chamilo LMS to version 2.0.0-RC.3 or later to remediate CVE-2026-34160.
*   Deploy the Sigma rule `Detect Chamilo LMS SSRF Attempt via Package URL` to identify attempts to exploit the SSRF vulnerability by monitoring for requests to `public/plugin/Pens/pens.php` with suspicious `package-url` values.
*   Monitor web server logs for requests to the PENS plugin endpoint (`public/plugin/Pens/pens.php`) containing the IP address `169.254.169.254` in the `package-url` parameter to detect access attempts to cloud metadata endpoints.
*   Implement network segmentation and restrict access to internal services from the Chamilo LMS server to limit the impact of potential SSRF attacks.
