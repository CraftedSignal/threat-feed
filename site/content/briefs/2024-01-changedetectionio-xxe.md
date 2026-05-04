---
title: changedetection.io XXE Vulnerability
slug: 2024-01-changedetectionio-xxe
description: A vulnerability in changedetection.io versions 0.54.9 and earlier allows a remote attacker to perform XML External Entity (XXE) attacks, potentially exposing sensitive local files.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - XXE
  - vulnerability
  - changedetection.io
vendors:
  - changedetection.io
products:
  - changedetection.io (<= 0.54.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-v7cp-2cx9-x793
rules:
  - title: Detect Changedetection.io XXE Vulnerability Attempt
    description: Detects potential XXE attacks against changedetection.io instances by monitoring web server logs for requests containing XML documents with suspicious entity declarations.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.002
    data_sources:
      - webserver
      - linux
  - title: Detect Changedetection.io XPath Filter Usage
    description: Detects requests that may be triggering the XPath filter within changedetection.io.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

An XML External Entity (XXE) vulnerability exists in changedetection.io version 0.54.9 and earlier. The vulnerability resides within the `xpath_filter()` function in `changedetectionio/html_tools.py:287`. This function creates an XML parser without disabling external entity resolution, external DTD loading, or network-backed entity lookup. An attacker can exploit this by controlling a watched XML/RSS response body and using an XPath include filter. Successful exploitation allows the attacker to read arbitrary local files from the system running changedetection.io, potentially leading to information disclosure. This issue was reported on May 4, 2026 (GHSA-v7cp-2cx9-x793) and assigned CVE-2026-41895.

## Attack Chain

1.  Attacker identifies a changedetection.io instance monitoring an XML/RSS feed.
2.  Attacker crafts a malicious XML/RSS response containing an external entity declaration referencing a local file (e.g., `/etc/passwd`).
3.  Attacker ensures the watched URL returns the malicious XML/RSS content.
4.  The changedetection.io instance fetches the XML/RSS content from the monitored URL.
5.  The application's stream detection identifies the content as XML/RSS.
6.  The XPath include filter is triggered, invoking the vulnerable `xpath_filter()` function.
7.  `etree.fromstring()` parses the untrusted XML bytes, resolving the external entity and reading the referenced local file.
8.  The contents of the local file are exposed in extracted watch output, diff history, or downstream notification channels.

## Impact

Successful exploitation of this XXE vulnerability (CVE-2026-41895) can lead to the disclosure of sensitive local files on the server running changedetection.io. The impact includes potential exposure of configuration files, credentials, or other sensitive data, which could be leveraged for further attacks or unauthorized access. While the number of affected installations is unknown, any instance of changedetection.io version 0.54.9 or earlier that monitors attacker-controlled XML/RSS feeds using XPath filters is potentially vulnerable.

## Recommendation

*   Upgrade changedetection.io to a version beyond 0.54.9 to remediate the vulnerability.
*   Apply the remediation steps suggested by the original report: Harden XML parser construction with `resolve_entities=False`, `load_dtd=False`, and `no_network=True`.
*   Implement the Sigma rule `Detect Changedetection.io XXE Vulnerability Attempt` to detect potential XXE attacks against changedetection.io instances by monitoring for suspicious XML parsing events.
*   Enable webserver logging to activate the rule above (logsource: category: webserver, product: linux).
