---
title: BrowserOperator Core Path Traversal Vulnerability (CVE-2026-7234)
slug: 2026-04-browseroperator-path-traversal
description: A path traversal vulnerability (CVE-2026-7234) exists in BrowserOperator browser-operator-core up to version 0.6.0, allowing remote attackers to read arbitrary files by manipulating the request.url argument in the startsWith function of scripts/component_server/server.js.
date: "2026-04-28T07:16:04Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path-traversal
  - web-application
  - cve-2026-7234
vendors:
  - BrowserOperator
products:
  - browser-operator-core (<= 0.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7234
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7234
  - https://vuldb.com/vuln/359843
rules:
  - title: Detect BrowserOperator Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability (CVE-2026-7234) in BrowserOperator browser-operator-core by identifying suspicious URL patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Double Encoded Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability (CVE-2026-7234) in BrowserOperator browser-operator-core by identifying suspicious double encoded URL patterns.
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

A path traversal vulnerability has been identified in BrowserOperator browser-operator-core versions up to 0.6.0. The vulnerability, designated as CVE-2026-7234, resides in the `startsWith` function within the `scripts/component_server/server.js` file. By manipulating the `request.url` argument, an attacker can bypass path restrictions and potentially access sensitive files on the server. The vulnerability can be exploited remotely, and a proof-of-concept exploit is publicly available. The BrowserOperator project has been notified, but a patch has not yet been released. Successful exploitation could lead to information disclosure and unauthorized access to system resources.

## Attack Chain

1.  The attacker identifies a vulnerable BrowserOperator browser-operator-core instance running a version prior to 0.6.0.
2.  The attacker crafts a malicious HTTP request targeting the `component_server/server.js` endpoint.
3.  The crafted request includes a manipulated `request.url` argument designed to bypass the `startsWith` function's intended path restrictions.
4.  The `startsWith` function fails to properly sanitize or validate the `request.url` input.
5.  The application uses the attacker-controlled `request.url` to construct a file path.
6.  The application attempts to read a file based on the constructed path, traversing directories outside of the intended scope.
7.  If successful, the contents of the targeted file are returned to the attacker in the HTTP response.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to read arbitrary files on the server hosting the BrowserOperator browser-operator-core application. This could lead to the disclosure of sensitive information, including configuration files, credentials, or source code. The lack of response from the project maintainers increases the risk of widespread exploitation, especially given the availability of a public exploit.

## Recommendation

*   Inspect webserver logs for HTTP requests containing path traversal patterns in the URL targeting the `component_server/server.js` endpoint to detect potential exploitation attempts. Deploy the Sigma rule `Detect BrowserOperator Path Traversal Attempt` to identify suspicious requests.
*   Monitor web server logs for unusual file access patterns originating from the BrowserOperator application.
*   Consider using a web application firewall (WAF) to filter out malicious requests targeting the vulnerable endpoint, mitigating the risk of CVE-2026-7234.
