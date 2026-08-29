---
title: XXE Vulnerability in MapFish Print
slug: 2026-08-mapfish-xxe
description: MapFish Print is susceptible to an XML External Entity (XXE) injection vulnerability via the GML layer processing feature, allowing attackers to perform arbitrary file reads or Server-Side Request Forgery (SSRF).
date: "2026-08-29T03:13:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xxe
  - cve-2026-55848
  - vulnerability
  - webserver
vendors:
  - MapFish
products:
  - print-lib (3.0.0-3.28.29, 3.29.0-3.30.31, 3.32.0-3.33.15, 3.34.0-4.0.4)
  - print-servlet (3.0.0-3.28.29, 3.29.0-3.30.31, 3.31.0-3.31.23, 3.32.0-3.33.15, 3.34.0-4.0.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: When using the Print feature its possible to send the attacker server url as url of the gml layer.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: XXE on MapFish Print allows reading arbitrary files of certain types.
    confidence_band: high
cves:
  - id: CVE-2026-55848
    cvss: 8.6
references:
  - https://github.com/advisories/GHSA-5v29-34h8-v68r
  - https://github.com/mapfish/mapfish-print/commit/13020c0fbc299e5f604e4e66066311c4bf04d507
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade MapFish Print to version 4.0.5 or later.
      owner: IT Operations
      due: 48h
      evidence: Source advisory lists 4.0.5 as fixed version.
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound internet access for MapFish Print service servers.
      owner: Network Security
      addresses: CVE-2026-55848
      evidence: Exploit requires server to fetch remote DTD file.
---

MapFish Print, a Java-based web application for generating printable reports, contains an XML External Entity (XXE) vulnerability identified as CVE-2026-55848. The issue originates from the way the print service processes GML layers. By submitting a JSON payload to the `/api/print3/print/mapviewer/buildreport.pdf` endpoint with a manipulated GML layer URL, an attacker can point the application to a remote, malicious DTD file. 

When processed, this configuration triggers the XXE, which can be leveraged to exfiltrate local files from the server, perform directory listing, or initiate SSRF attacks against internal network resources. The vulnerability affects multiple versions of the `print-lib` and `print-servlet` components within the 3.x and 4.x branches. This impact is significant for organizations deploying MapFish Print in cloud environments, as it may lead to the exposure of Kubernetes service account tokens or other sensitive system credentials.

## Attack Chain

1. The attacker stands up a remote server hosting a malicious PHP script (xxe.php) and an associated DTD file (evil.dtd).
2. The attacker constructs a JSON request for the MapFish Print `buildreport.pdf` endpoint.
3. The JSON request includes a `layers` object with the `type` set to `gml` and a `url` pointing to the attacker-controlled `xxe.php` script with a file path parameter (e.g., `/etc/passwd`).
4. The MapFish Print server initiates an HTTP request to the attacker-controlled `xxe.php` server to retrieve the XML configuration.
5. The attacker's server responds with an XML document containing the malicious DTD and the defined entity, which triggers the file read on the MapFish server.
6. The MapFish server attempts to load the file referenced by the entity, and the error processing mechanism (specifically 404 handler) returns the content of the target file in the response body.
7. The attacker receives the sensitive file contents directly in the HTTP response from the MapFish Print service.

## Impact

Successful exploitation allows for the unauthorized disclosure of local server files, including sensitive configuration files and credentials. Furthermore, the vulnerability supports SSRF, enabling attackers to interact with internal infrastructure, potentially bypassing network segmentation or accessing metadata services in cloud environments.

## Recommendation

1. Upgrade MapFish Print to the latest version (v4.0.5 or higher) to remediate CVE-2026-55848.
2. Implement an egress filtering policy on all MapFish Print servers to restrict outbound HTTP/HTTPS connections, preventing the application from fetching untrusted remote DTDs.
3. Deploy WAF rules to inspect JSON payloads sent to the print API for anomalous GML layer URLs, specifically looking for external domains or unusual URI parameters.
4. Review server logs for anomalous outbound HTTP requests originating from the MapFish Print application process.
