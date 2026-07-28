---
title: IBM WebSphere Application Server Liberty Path-Segment Injection Vulnerability (CVE-2026-15280)
slug: 2026-07-ibm-websphere-path-injection
description: A path-segment injection vulnerability (CVE-2026-15280) in the collective routing mechanism of IBM WebSphere Application Server - Liberty versions 17.0.0.3 through 26.0.0.8 ND Collective Controller allows an unauthenticated attacker to inject arbitrary path segments, potentially leading to information disclosure.
date: "2026-07-28T21:29:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - path-segment-injection
  - information-disclosure
  - websphere
  - ibm
vendors:
  - IBM
products:
  - WebSphere Application Server - Liberty 17.0.0.3
  - WebSphere Application Server - Liberty 17.0.0.4
  - WebSphere Application Server - Liberty 17.0.0.5
  - WebSphere Application Server - Liberty 17.0.0.6
  - WebSphere Application Server - Liberty 17.0.0.7
  - WebSphere Application Server - Liberty 17.0.0.8
  - WebSphere Application Server - Liberty 18.0.0.1
  - WebSphere Application Server - Liberty 18.0.0.2
  - WebSphere Application Server - Liberty 18.0.0.3
  - WebSphere Application Server - Liberty 18.0.0.4
  - WebSphere Application Server - Liberty 19.0.0.1
  - WebSphere Application Server - Liberty 19.0.0.2
  - WebSphere Application Server - Liberty 19.0.0.3
  - WebSphere Application Server - Liberty 19.0.0.4
  - WebSphere Application Server - Liberty 20.0.0.1
  - WebSphere Application Server - Liberty 20.0.0.2
  - WebSphere Application Server - Liberty 20.0.0.3
  - WebSphere Application Server - Liberty 20.0.0.4
  - WebSphere Application Server - Liberty 21.0.0.1
  - WebSphere Application Server - Liberty 21.0.0.2
  - WebSphere Application Server - Liberty 21.0.0.3
  - WebSphere Application Server - Liberty 21.0.0.4
  - WebSphere Application Server - Liberty 22.0.0.1
  - WebSphere Application Server - Liberty 22.0.0.2
  - WebSphere Application Server - Liberty 22.0.0.3
  - WebSphere Application Server - Liberty 22.0.0.4
  - WebSphere Application Server - Liberty 23.0.0.1
  - WebSphere Application Server - Liberty 23.0.0.2
  - WebSphere Application Server - Liberty 23.0.0.3
  - WebSphere Application Server - Liberty 23.0.0.4
  - WebSphere Application Server - Liberty 24.0.0.1
  - WebSphere Application Server - Liberty 24.0.0.2
  - WebSphere Application Server - Liberty 24.0.0.3
  - WebSphere Application Server - Liberty 24.0.0.4
  - WebSphere Application Server - Liberty 25.0.0.1
  - WebSphere Application Server - Liberty 25.0.0.2
  - WebSphere Application Server - Liberty 25.0.0.3
  - WebSphere Application Server - Liberty 25.0.0.4
  - WebSphere Application Server - Liberty 26.0.0.1
  - WebSphere Application Server - Liberty 26.0.0.2
  - WebSphere Application Server - Liberty 26.0.0.3
  - WebSphere Application Server - Liberty 26.0.0.4
  - WebSphere Application Server - Liberty 26.0.0.5
  - WebSphere Application Server - Liberty 26.0.0.6
  - WebSphere Application Server - Liberty 26.0.0.7
  - WebSphere Application Server - Liberty 26.0.0.8
cves:
  - id: CVE-2026-15280
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15280
  - https://www.ibm.com/support/pages/node/7281633
---

IBM has disclosed a path-segment injection vulnerability, identified as CVE-2026-15280, affecting its WebSphere Application Server - Liberty product. Specifically, versions 17.0.0.3 through 26.0.0.8 of the ND Collective Controller component are susceptible. This flaw resides within the collective routing mechanism, allowing an unauthenticated attacker to inject arbitrary path segments. This vulnerability is categorized as CWE-22, "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')," and carries a CVSS v3.1 Base Score of 7.5, indicating a high severity risk primarily due to its potential for high confidentiality impact. The vulnerability does not require authentication or user interaction for exploitation and can lead to unauthorized access to sensitive information on the affected server.

## Attack Chain

1. An unauthenticated attacker sends a specially crafted HTTP request to a vulnerable IBM WebSphere Application Server - Liberty instance.
2. The request is directed towards a component utilizing the collective routing mechanism of the server.
3. The attacker embeds malicious path segments within the request, designed to bypass normal validation.
4. Due to the path-segment injection vulnerability (CVE-2026-15280), the collective routing mechanism fails to properly sanitize or validate these injected segments.
5. This failure allows the attacker to manipulate the server's path resolution logic, enabling access to restricted directories or files.
6. The server processes the request with the injected path, leading to unauthorized disclosure of sensitive information from the file system.

## Impact

The successful exploitation of CVE-2026-15280 can lead to significant information disclosure. Attackers capable of exploiting this path-segment injection vulnerability could gain unauthorized access to critical configuration files, user data, server logs, or other sensitive information stored on the affected IBM WebSphere Application Server - Liberty instances. While the vulnerability does not directly enable integrity modification or availability impact, the exposure of confidential data can have severe consequences, including intellectual property theft, privacy breaches, and further system compromise through credential harvesting or detailed reconnaissance. Organizations using affected versions are at risk of data exfiltration and compliance violations.

## Recommendation

* Patch CVE-2026-15280 immediately by upgrading IBM WebSphere Application Server - Liberty to a fixed version as specified in the IBM Corporation advisory at `https://www.ibm.com/support/pages/node/7281633`.
* Review network logs for unusual HTTP requests targeting the collective routing mechanism or containing atypical path segments, particularly those involving `CWE-22` characteristics.
* Implement strong input validation and sanitization for all user-supplied data, especially in web application path parameters, to prevent future path-segment injection vulnerabilities.
