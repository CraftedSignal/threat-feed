---
title: OpenClaw SSRF Vulnerability in Zalo Plugin (CVE-2026-44116)
slug: 2026-05-openclaw-ssrf
description: OpenClaw before 2026.4.22 is vulnerable to server-side request forgery (SSRF) due to improper validation of outbound photo URLs in the Zalo plugin's sendPhoto function, allowing attackers to potentially access internal resources by providing malicious photo URLs to the Zalo Bot API.
date: "2026-05-06T20:16:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-44116
  - openclaw
  - zalo
vendors:
  - OpenClaw
products:
  - OpenClaw
  - Zalo plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-44116
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44116
  - https://github.com/openclaw/openclaw/commit/a65eb1b864b7630c1242a82de9e5799b80583c3f
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-2hh7-c75g-qj2r
  - https://www.vulncheck.com/advisories/openclaw-server-side-request-forgery-in-zalo-photo-url-validation
rules:
  - title: Detect OpenClaw Zalo Plugin SSRF Attempt
    description: Detects potential Server-Side Request Forgery (SSRF) attempts originating from an OpenClaw server by monitoring requests to internal IP addresses or domains.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Zalo Plugin SSRF Attempt - Internal Domain
    description: Detects potential Server-Side Request Forgery (SSRF) attempts originating from an OpenClaw server by monitoring requests to internal domains.
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
---

OpenClaw, a web application, is susceptible to a server-side request forgery (SSRF) vulnerability (CVE-2026-44116) affecting versions prior to 2026.4.22. The vulnerability resides within the Zalo plugin's sendPhoto function, specifically in how it validates outbound photo URLs. The absence of proper SSRF guard validation allows a malicious actor to craft photo URLs that, when processed by the Zalo Bot API, can bypass intended security controls. This can lead to unauthorized access to internal resources that would otherwise be protected. Successful exploitation enables an attacker to make requests on behalf of the server, potentially exposing sensitive data or enabling further malicious activity within the internal network.

## Attack Chain

1.  Attacker identifies an OpenClaw instance running a version prior to 2026.4.22 with the Zalo plugin enabled.
2.  The attacker crafts a malicious photo URL designed to target an internal resource.
3.  The attacker utilizes the Zalo Bot API to send a request including the crafted malicious photo URL to the sendPhoto function.
4.  The sendPhoto function attempts to retrieve the photo from the attacker-controlled URL without proper SSRF validation.
5.  The OpenClaw server makes an HTTP request to the internal resource specified in the malicious URL.
6.  The internal resource responds to the OpenClaw server, potentially disclosing sensitive information.
7.  The attacker retrieves the response from the internal resource, gaining unauthorized access to sensitive data.

## Impact

Successful exploitation of CVE-2026-44116 can lead to the exposure of sensitive internal resources. An attacker could potentially access internal databases, configuration files, or other services that are not intended to be exposed to the public internet. The specific impact depends on the nature of the internal resources accessible and could range from information disclosure to remote code execution if coupled with other vulnerabilities. The lack of specific victim numbers or targeted sectors in the report makes quantification difficult, but the high CVSS score suggests a significant potential for damage.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.22 or later to patch the SSRF vulnerability in the Zalo plugin's sendPhoto function as stated in the vulnerability description.
*   Deploy the Sigma rule `Detect OpenClaw Zalo Plugin SSRF Attempt` to monitor for suspicious requests to internal resources originating from the OpenClaw server.
*   Review and harden internal network segmentation to limit the impact of potential SSRF vulnerabilities as the successful exploitation could expose internal resources.
