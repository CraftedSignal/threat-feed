---
title: Open WebUI SSRF Vulnerability via IPv6/IPv4-mapped IPv6 Bypass
slug: 2026-05-open-webui-ssrf
description: Open WebUI is vulnerable to Server-Side Request Forgery (SSRF) due to insufficient validation in the `validate_url()` function, allowing authenticated users to access internal IPv4 and IPv6 addresses, potentially leading to IAM credential exfiltration.
date: "2026-05-14T20:20:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openwebui:open_webui:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - open-webui
  - vulnerability
vendors:
  - GE Vernova
products:
  - open-webui (<= 0.8.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-65958
    cvss: 8.5
    epss: 0.00082
references:
  - https://github.com/advisories/GHSA-4v7r-f4w8-8972
  - https://github.com/advisories/GHSA-c6xv-rcvw-v685
rules:
  - title: Detect Open WebUI SSRF Attempt via IPv4-mapped IPv6
    description: Detects attempts to exploit the Open WebUI SSRF vulnerability by using IPv4-mapped IPv6 addresses to bypass input validation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Open WebUI SSRF Attempt via Reserved IPv4 Range
    description: Detects attempts to exploit the Open WebUI SSRF vulnerability by using reserved IPv4 ranges.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI versions 0.8.12 and earlier contain a Server-Side Request Forgery (SSRF) vulnerability in the `validate_url()` function located in `backend/open_webui/retrieval/web/utils.py`. This flaw stems from the `validators` library not properly implementing the `private` keyword for IPv6 address validation, causing it to silently fail and allow all IPv6 addresses. Furthermore, IPv4-mapped IPv6 addresses (e.g., `::ffff:10.0.0.1`) bypass the IPv4 validation checks entirely. Several reserved IPv4 ranges, such as `0.0.0.0/8` and `100.64.0.0/10`, are also not blocked. This vulnerability affects multiple endpoints that rely on `validate_url()`, including `/api/v1/retrieval/process/web` and `/api/v1/images/edit`. Despite a previous patch attempt (GHSA-c6xv-rcvw-v685 / CVE-2025-65958), the issue was not fully resolved, leaving systems vulnerable to internal resource access and potential data exfiltration. Dor Konis of GE Vernova identified the IPv6 bypass, and wlayzz identified the unblocked IPv4 ranges.

## Attack Chain

1. An authenticated user logs into the Open WebUI application.
2. The user crafts a malicious request to an endpoint that utilizes the `validate_url()` function, such as `/api/v1/retrieval/process/web`.
3. The request includes a URL containing either a direct IPv6 address or an IPv4-mapped IPv6 address (e.g., `http://[::ffff:169.254.169.254]/`).
4. The `validate_url()` function in `backend/open_webui/retrieval/web/utils.py` attempts to validate the URL's IP address.
5. Due to the flawed validation logic, the IPv6 or IPv4-mapped IPv6 address bypasses the intended restrictions.
6. The server-side process makes an HTTP request to the attacker-specified internal IP address.
7. If the target is a cloud metadata service (e.g., AWS IMDSv1 at `169.254.169.254`), the server retrieves sensitive information, such as IAM credentials.
8. The attacker exfiltrates the obtained IAM credentials for unauthorized access to cloud resources.

## Impact

Successful exploitation allows any authenticated user to perform Server-Side Request Forgery (SSRF) attacks, accessing internal IPv4 and IPv6 addresses from the Open WebUI server process. This includes access to cloud metadata services, localhost-bound APIs, and other internal services. The reachability of IMDSv1 leads to the exfiltration of IAM credentials, enabling attackers to gain unauthorized access to cloud resources.

## Recommendation

*   Apply the recommended fix by replacing the `validators` library calls in the `validate_url()` function with the `ipaddress` module from Python's standard library as described in the advisory. This will ensure proper validation of IPv4 and IPv6 addresses, including private, loopback, link-local, multicast, reserved, and unspecified addresses.
*   Implement explicit blocks for IANA reserved IPv4 ranges (0.0.0.0/8, 100.64.0.0/10, 192.0.0.0/24, etc.) within the `validate_url()` function to prevent bypasses.
*   Deploy the Sigma rule `Detect Open WebUI SSRF Attempt via IPv4-mapped IPv6` to identify exploitation attempts targeting internal resources via IPv4-mapped IPv6 addresses.
*   Upgrade to a patched version of Open WebUI that incorporates the recommended fixes to address CVE-2026-45331 and prevent future SSRF attacks.
