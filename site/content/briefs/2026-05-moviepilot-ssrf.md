---
title: MoviePilot v2 Server-Side Request Forgery Vulnerability (CVE-2026-10107)
slug: 2026-05-moviepilot-ssrf
description: MoviePilot v2 is vulnerable to server-side request forgery (SSRF) in the image proxy endpoint, allowing authenticated attackers to request arbitrary URLs, enumerate internal services, and exfiltrate data from internal network resources by bypassing internal network protections.
date: "2026-05-29T18:18:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-10107
  - server-side request forgery
  - network
products:
  - MoviePilot v2
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1539
    technique_name: Resource Enumeration
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1539
    technique_name: Resource Enumeration
cves:
  - id: CVE-2026-10107
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10107
rules:
  - title: Detects CVE-2026-10107 Exploitation - SSRF Attempt via Image Proxy Endpoint
    description: Detects CVE-2026-10107 exploitation - attempts to exploit the SSRF vulnerability in MoviePilot v2 by sending requests to the image proxy endpoint targeting private IP addresses.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1539
    data_sources:
      - webserver
  - title: Detects CVE-2026-10107 Exploitation - SSRF Attempt to Common Internal Service Ports
    description: Detects CVE-2026-10107 exploitation - attempts to exploit the SSRF vulnerability in MoviePilot v2 to enumerate common internal service ports like those used by Jellyfin, Emby, or Plex.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1539
    data_sources:
      - webserver
  - title: Detects CVE-2026-10107 Exploitation - SSRF Attempt with File Scheme
    description: Detects CVE-2026-10107 exploitation - attempts to exploit the SSRF vulnerability in MoviePilot v2 using file scheme to read local files.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1539
    data_sources:
      - webserver
rules_count: 3
---

MoviePilot v2 is susceptible to a server-side request forgery (SSRF) vulnerability, identified as CVE-2026-10107, within its image proxy endpoint. This flaw allows authenticated attackers to craft malicious requests targeting internal network resources. The vulnerability stems from insufficient validation of URLs, specifically the `SecurityUtils.is_safe_url` function, which checks domain membership against an allowlist but fails to block private, loopback, or link-local addresses. By exploiting this, attackers can bypass intended network segregation, potentially enumerating internal services such as Jellyfin, Emby, or Plex, and exfiltrating sensitive data from internal network resources. This issue poses a significant risk to the confidentiality and integrity of data within the affected network.

## Attack Chain

1. An attacker authenticates to the MoviePilot v2 application.
2. The attacker crafts a malicious URL targeting an internal resource (e.g., a private IP address hosting a service like Jellyfin).
3. The attacker obtains a valid `resource_token` cookie.
4. The attacker sends a request to the image proxy endpoint with the crafted URL and the `resource_token` cookie.
5. The `SecurityUtils.is_safe_url` function checks if the domain in the crafted URL is present in the assembled allowlist but does not validate the IP address range (private, loopback, or link-local).
6. The image proxy endpoint processes the request without proper validation.
7. The MoviePilot server makes a request to the specified internal resource.
8. The attacker receives the response from the internal resource, potentially revealing sensitive information or allowing further exploitation.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-10107) could allow an attacker to enumerate internal services (Jellyfin, Emby, Plex) and potentially exfiltrate sensitive data from internal network resources. The impact includes potential disclosure of sensitive data, compromise of internal services, and further lateral movement within the network. The CVSS v3.1 base score for this vulnerability is 7.7, indicating a high severity.

## Recommendation

*   Deploy the Sigma rule to detect SSRF attempts by monitoring for requests to the image proxy endpoint with potentially malicious URLs targeting internal IP addresses or loopback addresses.
*   Apply the Sigma rule to detect potential enumeration of internal services through SSRF by monitoring requests to common service ports or paths from the MoviePilot server.
*   Implement stricter validation of URLs within the `SecurityUtils.is_safe_url` function to block private, loopback, and link-local addresses, preventing SSRF attacks.
*   Apply network segmentation and access controls to limit the MoviePilot server's access to only necessary internal resources.
