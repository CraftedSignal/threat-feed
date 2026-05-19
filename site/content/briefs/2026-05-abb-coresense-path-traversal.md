---
title: ABB CoreSense HM and CoreSense M10 Path Traversal Vulnerability (CVE-2025-3465)
slug: 2026-05-abb-coresense-path-traversal
description: A path traversal vulnerability (CVE-2025-3465) in ABB CoreSense HM and CoreSense M10 allows unauthenticated local users to access restricted directories, potentially leading to system compromise and information exposure; patch to CoreSense™ HM v2.3.4 and CoreSense™ M10 v1.4.1.31.
date: "2026-05-19T16:15:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - abb
vendors:
  - ABB
products:
  - CoreSense™ HM
  - CoreSense™ M10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-3465
    cvss: 7.1
    epss: 0.00018
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-01
  - https://www.cve.org/CVERecord?id=CVE-2025-3465
  - https://cwe.mitre.org/data/definitions/22.html
rules:
  - title: Detect ABB CoreSense HM/M10 Path Traversal Attempt
    description: Detects CVE-2025-3465 exploitation attempt — path traversal in ABB CoreSense HM/M10 web applications via local access.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect ABB CoreSense HM/M10 Path Traversal in Web Logs
    description: Detects CVE-2025-3465 exploitation — Path traversal attempts in web server logs indicating potential unauthorized file access in ABB CoreSense HM/M10.
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

ABB CoreSense HM and CoreSense M10 are vulnerable to a path traversal vulnerability (CVE-2025-3465). This vulnerability allows unauthenticated users with local access to the affected systems to gain unauthorized access to restricted directories. Successful exploitation of this vulnerability could lead to complete system compromise and the exposure of sensitive information. The vulnerability affects CoreSense™ HM versions up to 2.3.1 and 2.3.4, as well as CoreSense™ M10 versions up to 1.4.1.12 and 1.4.1.31. ABB has released updated versions (CoreSense™ HM v2.3.4 and CoreSense™ M10 v1.4.1.31) to address this vulnerability, urging users to apply the updates promptly. This poses a significant risk to organizations in critical infrastructure sectors like Food and Agriculture, Commercial Facilities, and Critical Manufacturing, where these products are deployed worldwide.

## Attack Chain

1.  Attacker gains local access to the machine hosting the vulnerable ABB CoreSense HM or CoreSense M10 web application, either through physical access or compromising a user account.
2.  Attacker crafts a malicious HTTP request containing a path traversal payload targeting a specific endpoint within the web application. This payload manipulates the file path to access restricted directories outside the intended scope.
3.  The vulnerable application fails to properly sanitize the provided file path, allowing the attacker to bypass access controls.
4.  The web server processes the manipulated request and attempts to read the file specified by the attacker-controlled path.
5.  The application retrieves and returns the contents of the targeted file, potentially containing sensitive configuration data, credentials, or other confidential information.
6.  Attacker analyzes the retrieved data to gather further information about the system, such as user accounts, installed software, and network configuration.
7.  The attacker uses the gathered information to escalate privileges and gain unauthorized access to other parts of the system.
8.  Attacker achieves complete system compromise and exfiltrates sensitive information.

## Impact

Successful exploitation of CVE-2025-3465 can lead to complete system compromise and exposure of sensitive information. This may enable attackers to gain unauthorized access to critical systems, disrupt operations, or steal sensitive data. Sectors such as Food and Agriculture, Commercial Facilities, and Critical Manufacturing, which rely on these systems, are at particular risk. The advisory does not mention specific victims or instances of exploitation, but it does state that unauthenticated local access is required.

## Recommendation

*   Apply the vendor-provided patches to upgrade to CoreSense™ HM v2.3.4 and CoreSense™ M10 v1.4.1.31 to remediate CVE-2025-3465.
*   Implement network segmentation and firewall rules to restrict local access to the ABB CoreSense HM and CoreSense M10 systems, as mentioned in the "Mitigating factors" section.
*   Deploy the Sigma rule `Detect ABB CoreSense HM/M10 Path Traversal Attempt` to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for suspicious requests containing path traversal sequences (e.g., "..", "%2e%2e") in the URI stem or query, as detected by the Sigma rule `Detect ABB CoreSense HM/M10 Path Traversal in Web Logs`.
