---
title: Detection of Exploitation Attempts Targeting Ivanti Connect Secure Bookmark Endpoint Vulnerabilities
slug: 2024-04-ivanti-connect-secure-bookmark-endpoint
description: Detection of access to the Ivanti Connect Secure bookmark endpoint associated with CVE-2023-46805 and CVE-2024-21887 via a GET request resulting in a 403 Forbidden response indicates a potential exploitation attempt.
date: "2024-04-29T12:00:00Z"
lastmod: "2026-10-13T17:40:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ivanti:connect_secure:9.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:connect_secure:9.1:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:connect_secure:22.1:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:connect_secure:22.2:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:connect_secure:22.3:r1:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:connect_secure:22.4:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:connect_secure:22.5:r2.1:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:connect_secure:22.6:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:policy_secure:9.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:policy_secure:9.1:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:policy_secure:22.1:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:policy_secure:22.2:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:policy_secure:22.3:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:policy_secure:22.4:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:policy_secure:22.5:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:policy_secure:22.6:r1:*:*:*:*:*:*
  - cpe:2.3:a:wpmet:wp_ultimate_review:*:*:*:*:*:wordpress:*:*
tags:
  - ivanti
  - cve-2023-46805
  - cve-2024-21887
  - vpn
  - exploitation
  - command-injection
  - authentication-bypass
vendors:
  - Ivanti
products:
  - Connect Secure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2023-46805
    cvss: 8.2
    epss: 0.99986
  - id: CVE-2024-21887
    cvss: 9.1
    epss: 0.99999
  - id: CVE-2023-46085
    cvss: 4.3
    epss: 0.00214
references:
  - https://github.com/RootUp/PersonalStuff/blob/master/http-vuln-cve2023-46805_2024_21887.nse
  - https://github.com/projectdiscovery/nuclei-templates/blob/c6b351e71b0fb0e40e222e97038f1fe09ac58194/http/misconfiguration/ivanti/CVE-2023-46085-CVE-2024-21887-mitigation-not-applied.yaml
  - https://github.com/rapid7/metasploit-framework/pull/18708/files
  - https://www.reddit.com/r/blueteamsec/comments/1x5177o/a_series_of_unauthenticated_events_chained/
rules:
  - title: Detect Ivanti Connect Secure Bookmark Endpoint Access
    description: Detects access to the Ivanti Connect Secure bookmark endpoint associated with CVE-2023-46805 and CVE-2024-21887 resulting in a 403 Forbidden response.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Ivanti Connect Secure Bookmark Endpoint Access (Empty Body)
    description: Detects access to the Ivanti Connect Secure bookmark endpoint associated with CVE-2023-46805 and CVE-2024-21887 resulting in a 403 Forbidden response and empty response body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-10-13T17:40:53Z"
    level: L2
    summary: added CVE-2023-46085 +2
    sources:
      - reddit-blueteamsec
    source_urls:
      - https://www.reddit.com/r/blueteamsec/comments/1x5177o/a_series_of_unauthenticated_events_chained/
---

This threat brief addresses exploitation attempts targeting Ivanti Connect Secure VPN appliances, specifically focusing on CVE-2023-46805 and CVE-2024-21887. These vulnerabilities allow for authentication bypass and command injection, potentially leading to unauthenticated remote code execution. The attacks target a specific endpoint related to web bookmarks, `/api/v1/configuration/users/user-roles/user-role/rest-userrole1/web/web-bookmarks/bookmark`. Detection focuses on identifying anomalous GET requests to this endpoint that result in a 403 Forbidden response. Successful exploitation grants attackers unauthorized access to the system, allowing them to execute commands, steal sensitive data, or deploy malicious payloads. Due to the critical nature of VPN appliances in network security, defenders must prioritize detecting and mitigating these exploitation attempts.

## Attack Chain

1. The attacker sends a crafted GET request to the vulnerable endpoint: `/api/v1/configuration/users/user-roles/user-role/rest-userrole1/web/web-bookmarks/bookmark`.
2. Due to the vulnerabilities (CVE-2023-46805 and CVE-2024-21887), the authentication checks are bypassed.
3. The server processes the malicious request and attempts to access or modify web bookmark configurations.
4. Due to improper input validation, a command injection vulnerability is triggered, allowing the attacker to inject arbitrary commands.
5. The server returns a `403 Forbidden` HTTP status code, indicating the request was blocked after the attempted exploitation. The response body is often empty.
6. The attacker leverages the command execution to perform reconnaissance activities, such as gathering system information using tools like `uname` or `ipconfig`.
7. The attacker attempts to establish persistence by creating new user accounts or modifying existing VPN configurations.
8. Finally, the attacker achieves their objective, which may include data exfiltration, lateral movement within the network, or deploying ransomware.

## Impact

Successful exploitation of CVE-2023-46805 and CVE-2024-21887 can lead to complete compromise of the Ivanti Connect Secure VPN appliance. This can result in unauthorized access to sensitive internal resources, data breaches, and disruption of VPN services. Given that VPNs are a critical component of network security, a successful attack can have widespread consequences. The number of affected organizations is potentially very high, with victims spanning multiple sectors, including government, finance, and critical infrastructure.

## Recommendation

*   Deploy the Sigma rule `Detect Ivanti Connect Secure Bookmark Endpoint Access` to identify potential exploitation attempts based on HTTP GET requests with 403 responses targeting the specific bookmark endpoint.
*   Inspect web server logs for requests matching the pattern `*/api/v1/configuration/users/user-roles/user-role/rest-userrole1/web/web-bookmarks/bookmark*` with a `403` status code, as described in the overview.
*   Investigate any alerts triggered by the provided Sigma rule or identified through manual log analysis, focusing on the source IP address (`Web.src` in the provided search query) and destination system (`Web.dest` in the provided search query).
*   Apply the official patches and mitigations provided by Ivanti for CVE-2023-46805 and CVE-2024-21887 on all affected Ivanti Connect Secure VPN appliances immediately, as this is the most effective way to prevent exploitation.
