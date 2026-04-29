---
title: OpenClaw SSRF Guard Bypass via IPv6 Special Use Ranges (CVE-2026-41361)
slug: 2026-04-openclaw-ssrf
description: OpenClaw before 2026.3.28 is vulnerable to a Server-Side Request Forgery (SSRF) guard bypass due to its failure to block four IPv6 special-use ranges, allowing attackers to craft URLs targeting internal or non-routable IPv6 addresses.
date: "2026-04-24T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - ssrf
  - cve-2026-41361
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Server-Side Request Forgery (SSRF)
cves:
  - id: CVE-2026-41361
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41361
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-g86v-f9qv-rh6m
  - https://www.vulncheck.com/advisories/openclaw-ssrf-guard-bypass-via-ipv6-special-use-ranges
rules:
  - title: Detect SSRF Attempt via IPv6 Special-Use Range
    description: Detects potential SSRF attempts by identifying HTTP requests containing IPv6 addresses from known special-use ranges.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
  - title: Detect SSRF Attempt via IPv6 Special-Use Range in POST Data
    description: Detects potential SSRF attempts by identifying HTTP POST requests containing IPv6 addresses from known special-use ranges in the request body.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw before version 2026.3.28 is susceptible to a Server-Side Request Forgery (SSRF) guard bypass vulnerability, identified as CVE-2026-41361. This flaw stems from the software's inability to properly block four specific IPv6 special-use ranges. By exploiting this vulnerability, attackers can craft malicious URLs that target internal or non-routable IPv6 addresses, effectively circumventing SSRF protections. This can allow attackers to probe internal services, access sensitive data, or potentially perform unauthorized actions within the internal network. Successful exploitation requires the application to process attacker-supplied URLs.

## Attack Chain

1.  Attacker identifies an OpenClaw instance running a version prior to 2026.3.28.
2.  The attacker crafts a malicious URL containing an IPv6 address from one of the four unblocked special-use ranges (e.g., targeting a link-local address).
3.  The crafted URL is submitted to the OpenClaw instance, potentially through a user-supplied input field or a request parameter.
4.  OpenClaw's SSRF guard fails to recognize the IPv6 address as internal or restricted due to the incomplete blocking.
5.  The OpenClaw server attempts to resolve the IPv6 address specified in the crafted URL.
6.  The server sends a request to the internal resource or service associated with the malicious IPv6 address.
7.  The server receives a response from the internal resource.
8.  The attacker obtains sensitive information from the internal resource or uses the vulnerable server to pivot to other internal systems.

## Impact

Successful exploitation of this SSRF vulnerability can lead to the exposure of sensitive internal information, such as configuration files, database credentials, or API keys. An attacker could also leverage the vulnerable server to access and interact with other internal services, potentially leading to lateral movement within the network. There is no indication of the number of victims or sectors affected at this time, but the potential impact includes unauthorized data access and compromised internal systems.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.28 or later to remediate the SSRF guard bypass vulnerability described in CVE-2026-41361.
*   Implement network segmentation and access controls to limit the impact of potential SSRF vulnerabilities by restricting access to sensitive internal resources.
*   Monitor web server logs for requests containing IPv6 addresses from special-use ranges, using a rule similar to the Sigma rule provided, and investigate any suspicious activity.
*   Deploy the provided Sigma rule to detect exploitation attempts. Tune it for your specific environment.
