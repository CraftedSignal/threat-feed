---
title: Across DR-810 Unauthenticated File Disclosure Vulnerability
slug: 2026-04-across-dr810-file-disclosure
description: Across DR-810 routers are vulnerable to unauthenticated file disclosure, allowing remote attackers to download the rom-0 backup file containing sensitive information, such as router passwords and configuration data, via a simple GET request to the rom-0 endpoint.
date: "2026-04-12T13:16:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2019-25706
  - file-disclosure
  - router
  - network
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2019-25706
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25706
  - http://www.ac.i8i.ir/
  - https://www.exploit-db.com/exploits/46132
  - https://www.vulncheck.com/advisories/across-dr-810-rom-0-unauthenticated-file-disclosure
iocs:
  - type: url
    value: http://www.ac.i8i.ir/
ioc_counts:
  url: 1
rules:
  - title: Across DR-810 Rom-0 File Disclosure Attempt
    description: Detects attempts to download the rom-0 backup file from Across DR-810 routers.
    platform: sigma
    severity: critical
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
  - title: Across DR-810 Rom-0 File Download Response
    description: Detects successful downloads of the rom-0 backup file from Across DR-810 routers based on response size.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Across DR-810 router contains an unauthenticated file disclosure vulnerability (CVE-2019-25706) that allows remote attackers to retrieve sensitive information. By sending a simple GET request to the `/rom-0` endpoint, an attacker can download a backup file containing router passwords, configuration details, and potentially other sensitive data. This vulnerability exists because the `/rom-0` endpoint does not require authentication, allowing anyone with network access to the router to retrieve the backup file. Successful exploitation leads to complete compromise of the device's configuration and potential lateral movement within the network if credentials are reused. This vulnerability was published on 2026-04-12.

## Attack Chain

1.  Attacker identifies an Across DR-810 router exposed on the network.
2.  Attacker crafts an HTTP GET request targeting the `/rom-0` endpoint.
3.  The router responds with the `rom-0` backup file without requiring authentication.
4.  Attacker downloads the `rom-0` backup file.
5.  Attacker decompresses the downloaded `rom-0` file, which is likely compressed to reduce size.
6.  The attacker parses the decompressed file to extract sensitive information such as router passwords.
7.  Attacker uses the extracted router passwords to gain administrative access to the router's web interface.

## Impact

Successful exploitation of this vulnerability allows attackers to retrieve sensitive information, including router passwords and configuration data. This can lead to complete compromise of the affected router. An attacker can then modify router settings, intercept network traffic, or potentially use the compromised router as a pivot point to access other systems on the network. If the router passwords are reused across multiple systems, the impact could extend beyond the compromised router, affecting other devices and services.

## Recommendation

*   Monitor web server logs for requests to the `/rom-0` endpoint on Across DR-810 routers to detect potential exploitation attempts using the provided Sigma rule.
*   Inspect network traffic for unusual downloads from Across DR-810 routers, focusing on responses from the `/rom-0` endpoint.
*   Block access to the `/rom-0` endpoint on Across DR-810 routers via firewall rules to prevent unauthorized access.
*   Review the provided reference URLs for additional context and potential mitigation strategies.
