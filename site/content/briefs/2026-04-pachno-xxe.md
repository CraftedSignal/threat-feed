---
title: Pachno 1.0.6 XML External Entity Injection Vulnerability
slug: 2026-04-pachno-xxe
description: Pachno 1.0.6 is vulnerable to XML external entity injection, allowing unauthenticated attackers to read arbitrary files by injecting malicious XML entities into wiki content due to unsafe XML parsing in the TextParser helper.
date: "2026-04-14T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - xxe
  - cve-2026-40042
  - pachno
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-40042
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40042
  - https://www.vulncheck.com/advisories/pachno-wiki-textparser-xml-external-entity-injection
  - https://www.zeroscience.mk/en/vulnerabilities/ZSL-2026-5984.php
iocs:
  - type: url
    value: https://www.zeroscience.mk/en/vulnerabilities/ZSL-2026-5984.php
ioc_counts:
  url: 1
rules:
  - title: Detect XML External Entity Injection Attempts via URI
    description: Detects potential XML External Entity (XXE) injection attempts by identifying requests containing XML entity declarations in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1566.003
    data_sources:
      - webserver
      - linux
  - title: Detect XML External Entity Injection Attempts via Request Body
    description: Detects potential XML External Entity (XXE) injection attempts by identifying requests containing XML entity declarations in the request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1566.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Pachno 1.0.6 is susceptible to an XML External Entity (XXE) injection vulnerability, identified as CVE-2026-40042. This flaw resides in the TextParser helper component, where unsafe XML parsing occurs. An unauthenticated attacker can exploit this vulnerability to read arbitrary files from the server. The attack involves injecting malicious XML entities into various parts of the application, including wiki table syntax, issue descriptions, comments, and wiki articles. The vulnerability is triggered by the use of the simplexml_load_string() function without proper restrictions (LIBXML_NONET), enabling the resolution of external entities. This issue poses a significant risk as it allows unauthorized access to sensitive data stored on the server.

## Attack Chain

1.  An unauthenticated attacker identifies a Pachno 1.0.6 instance.
2.  The attacker crafts a malicious XML payload containing an external entity declaration. This payload aims to read a sensitive file on the server, such as `/etc/passwd`.
3.  The attacker injects the malicious XML payload into a wiki page, issue description, or comment using wiki table syntax or inline tags.
4.  The application's TextParser helper processes the injected content using simplexml_load_string() without the LIBXML_NONET flag.
5.  The XML parser attempts to resolve the external entity, initiating a request to read the specified file.
6.  The targeted file's contents are embedded into the XML response due to the XXE vulnerability.
7.  The attacker retrieves the parsed XML response, which now contains the content of the targeted file, thus achieving unauthorized file access.
8.  The attacker can repeat this process to access other sensitive files, potentially gaining critical information about the system and its configuration.

## Impact

Successful exploitation of this XXE vulnerability (CVE-2026-40042) in Pachno 1.0.6 allows an unauthenticated attacker to read arbitrary files from the server. The impact can range from exposing sensitive configuration files and application code to potentially gaining access to user credentials or other confidential data. This information could be used for further malicious activities, such as lateral movement within the network or data exfiltration. Given the ease of exploitation and the potential for significant data leakage, this vulnerability represents a critical risk.

## Recommendation

*   Upgrade to a patched version of Pachno that addresses CVE-2026-40042 by implementing proper XML parsing and disabling external entity resolution.
*   Implement input validation and sanitization to prevent the injection of malicious XML payloads into wiki pages, issue descriptions, and comments.
*   Monitor web server logs for requests containing XML entity declarations, which may indicate attempted exploitation of this vulnerability. See the provided Sigma rule for guidance.
*   Block the domains `www.vulncheck.com` and `www.zeroscience.mk` at the network level to prevent access to related advisory information, hindering attacker reconnaissance.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
