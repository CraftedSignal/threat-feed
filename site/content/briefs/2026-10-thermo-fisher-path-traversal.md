---
title: Path Traversal Vulnerability in Thermo Fisher Torrent Suite Software
slug: 2026-10-thermo-fisher-path-traversal
description: An authenticated path traversal vulnerability in Thermo Fisher Torrent Suite Software (CVE-2026-107777) allows remote attackers to read arbitrary files from the affected server.
date: "2026-10-15T17:00:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - cve-2026-107777
  - medical-devices
  - ics
vendors:
  - Thermo Fisher
products:
  - Torrent Suite Software (<= 5.18)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The affected product is vulnerable to a path traversal, which could allow an authenticated attacker to read arbitrary files on the Torrent Server.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-288-01
  - https://www.cve.org/CVERecord?id=CVE-2026-107777
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Torrent Suite Software to 5.22 or later
      owner: IT Operations
      due: 24h
      evidence: Vendor fix recommended in CISA advisory
  mitigation_plan:
    - priority: immediate
      action: Isolate Torrent Suite Server behind firewalls and restrict public access
      owner: IT Operations
      addresses: CVE-2026-107777
      evidence: CISA recommended practices
---

Thermo Fisher Torrent Suite Software versions 5.18 and earlier contain a path traversal vulnerability (CVE-2026-107777) identified in the Healthcare and Public Health sector. This vulnerability stems from improper input validation, which allows an authenticated attacker to manipulate file path parameters. By submitting crafted requests, an attacker can access arbitrary files on the Torrent Server that are accessible to the web service account. Given the nature of the application, which is used in critical healthcare environments, unauthorized access to sensitive configuration, system, or medical data poses a significant security risk. The vendor has released a fix and recommends upgrading to version 5.22 or later to mitigate this issue.

## Attack Chain

1. Attacker obtains valid credentials for the Torrent Suite Software application.
2. Attacker interacts with the web interface to identify input parameters that handle file paths.
3. Attacker crafts a malicious HTTP request containing path traversal sequences (e.g., ../../).
4. Attacker sends the crafted request to the vulnerable web endpoint.
5. The application fails to sanitize the path, resolving the directory traversal.
6. The web service retrieves the contents of the targeted file.
7. The application returns the contents of the unauthorized file in the HTTP response.
8. Attacker gains access to sensitive system or application files for further reconnaissance or exfiltration.

## Impact

Successful exploitation could result in the disclosure of sensitive files residing on the Torrent Server. This vulnerability affects Torrent Suite Software versions 5.18 and earlier globally. Impacted organizations in the healthcare sector could face exposure of clinical data, configuration files, or credentials stored on the server, potentially leading to a broader compromise of laboratory workflows or network environments.

## Recommendation

* Upgrade Thermo Fisher Torrent Suite Software to version 5.22 or later immediately as recommended by the vendor.
* Restrict network access to the Torrent Suite Software web interface, ensuring it is not reachable from the public internet.
* Implement firewall rules to isolate control system networks from general business networks.
* Audit web server logs for anomalous requests containing path traversal patterns (e.g., encoded or repeated '../' sequences) directed at application endpoints.
* Enforce strong authentication controls to prevent unauthorized access, as the vulnerability requires an authenticated session.
