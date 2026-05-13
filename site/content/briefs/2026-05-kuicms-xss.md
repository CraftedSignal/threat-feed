---
title: Kuicms Php EE 2.0 Persistent Cross-Site Scripting Vulnerability (CVE-2020-37222)
slug: 2026-05-kuicms-xss
description: Kuicms Php EE 2.0 is vulnerable to persistent cross-site scripting (CVE-2020-37222), allowing unauthenticated attackers to inject malicious scripts via the bbs reply endpoint, leading to arbitrary script execution in users' browsers.
date: "2026-05-13T16:19:24Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - xss
  - cve-2020-37222
  - kuicms
vendors:
  - Kuicms
products:
  - Kuicms Php EE
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2020-37222
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37222
  - https://kuicms.com
  - https://kuicms.com/kuicms.zip
  - https://www.exploit-db.com/exploits/48526
  - https://www.vulncheck.com/advisories/kuicms-php-ee-persistent-cross-site-scripting-via-bbs-reply
rules:
  - title: Detect CVE-2020-37222 Exploitation Attempt - Kuicms Php EE BBS Reply XSS
    description: Detects attempts to exploit CVE-2020-37222 by injecting malicious scripts into the Kuicms Php EE bbs reply endpoint.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2020-37222 Exploitation - Kuicms Php EE BBS Reply XSS with Obfuscation
    description: Detects attempts to exploit CVE-2020-37222 using obfuscated or encoded JavaScript payloads within the Kuicms Php EE bbs reply endpoint.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Kuicms Php EE 2.0 is susceptible to a persistent cross-site scripting (XSS) vulnerability. This flaw allows unauthenticated attackers to inject malicious JavaScript code into the application's database, which is then executed in the browsers of users who interact with the affected content. The vulnerability resides within the bbs reply functionality, specifically through the `/web/?c=bbs&a=reply` endpoint. An attacker can craft a POST request containing malicious HTML and JavaScript payloads within the `content` parameter. The vulnerability was reported on May 13, 2026, and poses a risk to organizations using the vulnerable Kuicms version, potentially leading to account compromise, data theft, and website defacement.

## Attack Chain

1.  An unauthenticated attacker identifies the `/web/?c=bbs&a=reply` endpoint.
2.  The attacker crafts a POST request to `/web/?c=bbs&a=reply`.
3.  The POST request includes a `content` parameter containing malicious HTML and JavaScript code.
4.  The server-side application fails to properly sanitize the input provided in the `content` parameter.
5.  The malicious payload is stored in the application's database.
6.  A user views the bbs reply containing the malicious payload.
7.  The malicious JavaScript code is executed within the user's browser, potentially stealing cookies or redirecting the user to a malicious website.
8.  The attacker gains control of the user's session or injects further malicious content into the website.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to inject malicious scripts into the Kuicms Php EE 2.0 application. This can lead to a variety of impacts, including account compromise, data theft, website defacement, and further propagation of malicious content. Given the CVSS v3.1 score of 7.2, this vulnerability poses a significant risk to organizations using the affected software.

## Recommendation

*   Apply any available patches or updates provided by Kuicms to address CVE-2020-37222.
*   Implement robust input validation and sanitization mechanisms to prevent XSS attacks, focusing on the `content` parameter of the `/web/?c=bbs&a=reply` endpoint.
*   Deploy the provided Sigma rule to detect potential exploitation attempts targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious POST requests to `/web/?c=bbs&a=reply` containing HTML or JavaScript payloads.
