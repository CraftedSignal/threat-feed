---
title: OpenClaw Server-Side Request Forgery Vulnerability (CVE-2026-35629)
slug: 2026-04-openclaw-ssrf
description: OpenClaw before 2026.3.25 is vulnerable to server-side request forgery (SSRF), allowing attackers to access restricted resources by exploiting improperly guarded base URLs in channel extensions.
date: "2026-04-09T22:16:31Z"
severities:
  - high
tags:
  - ssrf
  - openclaw
  - cve-2026-35629
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35629
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35629
  - https://github.com/openclaw/openclaw/commit/f92c92515bd439a71bd03eb1bc969c1964f17acf
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-rhfg-j8jq-7v2h
  - https://www.vulncheck.com/advisories/openclaw-server-side-request-forgery-via-unguarded-configured-base-urls-in-channel-extensions
rules:
  - title: Detect Suspicious OpenClaw SSRF Attempt
    description: Detects potential SSRF attempts against OpenClaw by identifying requests containing localhost or internal IP addresses in the query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Channel Extension SSRF via Fetch Call
    description: Detects attempts to exploit SSRF in OpenClaw channel extensions by monitoring for requests that try to access internal resources using fetch calls.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.25 are susceptible to a server-side request forgery (SSRF) vulnerability, identified as CVE-2026-35629. This flaw resides within multiple channel extensions, where configured base URLs are not adequately protected against SSRF attacks. An attacker can leverage this vulnerability by exploiting unprotected `fetch()` calls directed towards configured endpoints. This allows the attacker to rebind requests to internal, restricted destinations, gaining unauthorized access to sensitive resources. Successful exploitation could lead to information disclosure or further internal network compromise. Defenders should prioritize patching OpenClaw installations to version 2026.3.25 or later.

## Attack Chain

1.  The attacker identifies an OpenClaw instance running a vulnerable version (prior to 2026.3.25).
2.  The attacker discovers an unprotected channel extension that utilizes `fetch()` calls with a configurable base URL.
3.  The attacker crafts a malicious request to the vulnerable channel extension, injecting a URL pointing to an internal resource or service (e.g., `http://localhost/admin`).
4.  The OpenClaw application, without proper validation, uses the attacker-supplied URL in a `fetch()` call.
5.  The `fetch()` call is executed by the server, accessing the internal resource specified in the attacker's payload.
6.  The response from the internal resource is returned to the attacker, potentially exposing sensitive information or allowing for further exploitation.
7.  The attacker analyzes the response data to identify further internal targets or sensitive data.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-35629) in OpenClaw installations can lead to unauthorized access to internal resources, potentially exposing sensitive information such as configuration files, internal application data, or credentials. This could allow the attacker to pivot further into the internal network, potentially leading to lateral movement, data exfiltration, or other malicious activities. The vulnerability affects any OpenClaw instance running a version prior to 2026.3.25.

## Recommendation

*   Upgrade OpenClaw installations to version 2026.3.25 or later to remediate CVE-2026-35629.
*   Implement strict input validation on all configurable base URLs used in channel extensions to prevent SSRF attacks.
*   Deploy the Sigma rule `Detect Suspicious OpenClaw SSRF Attempt` to identify potential exploitation attempts based on HTTP request patterns.
*   Monitor web server logs for unusual or unexpected requests to internal resources, indicative of SSRF activity, using the `webserver` log source.
