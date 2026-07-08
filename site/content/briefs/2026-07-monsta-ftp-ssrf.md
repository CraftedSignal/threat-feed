---
title: 'CVE-2026-60105: Monsta FTP SSRF Vulnerability Leading to Credential Disclosure'
slug: 2026-07-monsta-ftp-ssrf
description: An unauthenticated attacker can exploit CVE-2026-60105, a Server-Side Request Forgery vulnerability in Monsta FTP before 2.14.5, by leveraging an incomplete IP blocklist check with IPv4-mapped IPv6 addresses to force the server to issue HTTP requests to internal services and write responses to an attacker-controlled FTP destination, potentially enabling retrieval of cloud instance metadata credentials.
date: "2026-07-08T21:19:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - server-side-request-forgery
  - vulnerability
  - web-application
  - credential-access
vendors:
  - Monsta FTP
products:
  - Monsta FTP < 2.14.5
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can obtain a CSRF token from the public getSystemVars endpoint and submit a fetchRemoteFile request with a source URL resolving to an IPv4-mapped address, causing the server to issue HTTP requests to internal services
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: ""
    evidence: enabling retrieval of cloud instance metadata credentials.
    confidence_band: high
cves:
  - id: CVE-2026-60105
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60105
rules:
  - title: Detects CVE-2026-60105 Exploitation - Monsta FTP SSRF via IPv4-mapped IPv6
    description: Detects CVE-2026-60105 exploitation where an unauthenticated attacker abuses the fetchRemoteFile action with an IPv4-mapped IPv6 address in the source URL to bypass IP blocklists and trigger SSRF, potentially leading to cloud credential disclosure.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1190
      - T1552.006
    data_sources:
      - webserver
rules_count: 1
---

Monsta FTP versions prior to 2.14.5 are vulnerable to a Server-Side Request Forgery (SSRF) flaw, identified as CVE-2026-60105. This vulnerability stems from an incomplete IP blocklist check within the `isBlockedIP()` function, which fails to correctly identify and block embedded IPv4 addresses present in IPv4-mapped IPv6 address formats. An unauthenticated attacker can leverage a publicly accessible endpoint, `getSystemVars`, to obtain a CSRF token. With this token, the attacker can then submit a crafted request to the `fetchRemoteFile` action. By specifying a source URL that resolves to an IPv4-mapped IPv6 address, the attacker can bypass Monsta FTP's internal IP filtering. This forces the vulnerable Monsta FTP server to initiate HTTP requests to internal network services, such as cloud instance metadata APIs, and then relay the responses to an attacker-controlled FTP server, leading to potential exposure of sensitive cloud credentials.

## Attack Chain

1. An unauthenticated attacker accesses the public `/getSystemVars` endpoint on the vulnerable Monsta FTP instance to retrieve a CSRF token.
2. The attacker crafts a malicious `POST` request targeting the `fetchRemoteFile` action, including the obtained CSRF token.
3. Within the `fetchRemoteFile` request, the attacker specifies a `sourceUrl` parameter containing an IPv4-mapped IPv6 address (e.g., `http://[::ffff:169.254.169.254]/latest/meta-data/`) pointing to an internal service, such as a cloud instance metadata API.
4. The Monsta FTP server's `isBlockedIP()` function performs an incomplete IP blocklist check, failing to detect the embedded internal IPv4 address within the IPv4-mapped IPv6 format.
5. Monsta FTP then initiates an HTTP GET request from the server itself to the internal `sourceUrl` specified by the attacker, effectively bypassing network segmentation.
6. The server receives the response from the internal service (e.g., cloud metadata credentials).
7. Monsta FTP subsequently writes this retrieved internal service response to an attacker-controlled FTP destination specified in the `fetchRemoteFile` request.
8. The attacker retrieves the sensitive cloud instance metadata credentials from their controlled FTP server, achieving credential access.

## Impact

The successful exploitation of CVE-2026-60105 by an unauthenticated attacker allows for Server-Side Request Forgery (SSRF), which can lead to significant compromise. The primary impact is the unauthorized retrieval of sensitive data, specifically cloud instance metadata credentials. If obtained, these credentials could grant the attacker extensive access to cloud resources, including virtual machines, storage buckets, and other cloud services associated with the compromised instance. This could result in further lateral movement, data exfiltration, or even complete takeover of the affected cloud environment, depending on the scope of the exposed credentials.

## Recommendation

* Patch CVE-2026-60105 immediately by upgrading Monsta FTP to version 2.14.5 or later.
* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect attempts to exploit CVE-2026-60105.
* Enable comprehensive web server logging for your Monsta FTP instance to capture `cs-uri-stem` and `cs-uri-query` for all requests, particularly those hitting the `/index.php` path with `action=fetchRemoteFile`.
