---
title: WWBN AVideo SSRF Vulnerability (CVE-2026-41060)
slug: 2024-01-avideo-ssrf
description: WWBN AVideo versions 29.0 and below are vulnerable to Server-Side Request Forgery (SSRF) due to an insufficient hostname check in the `isSSRFSafeURL()` function, allowing attackers to reach arbitrary ports on the AVideo server and exfiltrate data.
date: "2024-01-19T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - avideo
  - cve-2026-41060
  - web-application
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41060
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41060
rules:
  - title: Detect AVideo SSRF Attempt via Non-Standard Port
    description: Detects potential SSRF attempts against AVideo by identifying HTTP requests to the AVideo server's hostname with a non-standard port (excluding 80 and 443).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo SSRF - Saving Response to Webroot
    description: Detects potential AVideo SSRF exploitation by monitoring for log entries indicating a file save operation with a recognized SSRF trigger URL to the webroot directory.
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

WWBN AVideo, an open-source video platform, is susceptible to a Server-Side Request Forgery (SSRF) vulnerability, identified as CVE-2026-41060, in versions 29.0 and below. The vulnerability resides within the `isSSRFSafeURL()` function located in `objects/functions.php`. This function contains a flawed same-domain shortcircuit (lines 4290-4296) that permits any URL whose hostname matches `webSiteRootURL` to bypass SSRF protections. The insufficient check only compares the hostname and neglects the port, enabling an attacker to target arbitrary ports on the AVideo server by using the site's public hostname with a non-standard port. Successful exploitation allows the attacker to save the response body to a publicly accessible path, resulting in full data exfiltration. The vulnerability is patched in commit a0156a6398362086390d949190f9d52a823000ba. Defenders should prioritize patching vulnerable instances to prevent unauthorized data access and potential system compromise.

## Attack Chain

1. An attacker identifies an AVideo instance running version 29.0 or below.
2. The attacker crafts a malicious URL using the target AVideo server's hostname, but specifies a non-standard port (e.g., `https://target-avideo.com:1337`).
3. The attacker injects the crafted URL into a feature that utilizes the `isSSRFSafeURL()` function, such as a video import or URL preview functionality.
4. The `isSSRFSafeURL()` function incorrectly validates the URL due to the hostname match, bypassing the intended SSRF protections.
5. The AVideo server initiates a request to the attacker-controlled port (e.g., 1337) on the AVideo server itself.
6. The attacker configures a listener on the specified port to capture sensitive information or internal service responses.
7. The response body from the internal request is saved to a web-accessible path on the AVideo server.
8. The attacker accesses the web-accessible path to retrieve the exfiltrated data.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-41060) can lead to the exposure of sensitive information stored on the AVideo server or accessible via internal network resources. An attacker can potentially access internal services, databases, or configuration files. Depending on the nature of the exposed data, this could result in data breaches, unauthorized access to user accounts, or complete system compromise. Given the open-source nature of AVideo, a widespread vulnerability such as this could affect a significant number of installations, impacting organizations across various sectors using the platform for video hosting and distribution.

## Recommendation

*   Apply the patch from commit a0156a6398362086390d949190f9d52a823000ba to remediate the SSRF vulnerability (CVE-2026-41060).
*   Inspect web server logs for requests containing the AVideo server's hostname with non-standard ports to identify potential exploitation attempts. Deploy the provided Sigma rule targeting this behavior.
*   Implement network segmentation to limit the impact of potential SSRF attacks by restricting access to internal resources from the AVideo server.
*   Regularly audit and update all third-party software and libraries used by AVideo to address known security vulnerabilities.
