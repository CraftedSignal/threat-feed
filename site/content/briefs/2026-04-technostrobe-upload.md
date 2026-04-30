---
title: Technostrobe HI-LED-WR120-G2 Unrestricted File Upload Vulnerability (CVE-2026-5573)
slug: 2026-04-technostrobe-upload
description: CVE-2026-5573 allows remote attackers to perform unrestricted file uploads on Technostrobe HI-LED-WR120-G2 devices by manipulating the 'cwd' argument when interacting with the /fs file.
date: "2026-04-05T15:16:41Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - CVE-2026-5573
  - file-upload
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5573
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5573
  - https://github.com/shiky8/my--cve-vulnerability-research/blob/main/my_VulnDB_cves/CVE-TECHNOSTROBE-05-FileUpload.md
  - https://vuldb.com/submit/783326
  - https://vuldb.com/vuln/355343
  - https://vuldb.com/vuln/355343/cti
iocs:
  - type: url
    value: https://github.com/shiky8/my--cve-vulnerability-research/blob/main/my_VulnDB_cves/CVE-TECHNOSTROBE-05-FileUpload.md
  - type: url
    value: https://vuldb.com/submit/783326
  - type: url
    value: https://vuldb.com/vuln/355343
  - type: url
    value: https://vuldb.com/vuln/355343/cti
ioc_counts:
  url: 4
rules:
  - title: Detect Suspicious cwd Parameter Manipulation in /fs Endpoint
    description: Detects attempts to manipulate the `cwd` parameter in requests to the `/fs` endpoint, potentially indicating an exploitation attempt for CVE-2026-5573.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Upload of Common Web Shells
    description: Detects the upload of common web shell file extensions to the /fs endpoint.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-5573, has been identified in Technostrobe HI-LED-WR120-G2 version 5.5.0.1R6.03.30. This flaw allows unauthenticated, remote attackers to upload arbitrary files to the device due to improper handling of the 'cwd' argument when accessing the `/fs` file. Publicly available exploits exist, increasing the risk of widespread exploitation. The vendor was notified but did not respond. This vulnerability poses a significant threat due to the potential for complete system compromise, including remote code execution and data exfiltration.

## Attack Chain

1.  The attacker identifies a Technostrobe HI-LED-WR120-G2 device running the vulnerable firmware version 5.5.0.1R6.03.30.
2.  The attacker sends a crafted HTTP request to the `/fs` endpoint, manipulating the `cwd` argument.
3.  The manipulated `cwd` argument bypasses access controls, allowing the attacker to specify an arbitrary upload directory.
4.  The attacker uploads a malicious file, such as a web shell or executable, to the specified directory.
5.  The attacker accesses the uploaded file via a web browser or other means.
6.  If the uploaded file is executable (e.g., a web shell), the attacker executes arbitrary commands on the device with the privileges of the web server.
7.  The attacker leverages the gained access to escalate privileges, install persistent backdoors, or exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2026-5573 allows attackers to gain complete control over affected Technostrobe HI-LED-WR120-G2 devices. This can lead to data breaches, system disruption, or the device being used as a foothold for further attacks within the network. The lack of vendor response and the availability of public exploits make this vulnerability particularly dangerous.

## Recommendation

*   Monitor web server logs for suspicious requests to the `/fs` endpoint with unusual `cwd` parameter values. Use the provided Sigma rule to detect such activity.
*   Inspect uploaded files for malicious content. Deploy the file upload detection Sigma rule to identify potential web shells.
*   Block connections to the identified malicious URLs to prevent exploit attempts (see IOCs).
