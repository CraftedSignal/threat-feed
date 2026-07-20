---
title: 'CVE-2026-16324: Metasoft MetaCRM Unrestricted File Upload Vulnerability'
slug: 2026-07-metacrm-unrestricted-upload
description: A high-severity vulnerability, CVE-2026-16324, exists in Metasoft MetaCRM up to version 6.4.0 Beta06, allowing remote attackers to perform unrestricted file uploads by manipulating the 'File' argument within the `/business/qnaire/upload.jsp` component, which can lead to webshell deployment and remote code execution; a public exploit is available, increasing the risk of attack.
date: "2026-07-20T22:18:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - rce
  - unrestricted-upload
  - web-vulnerability
  - metacrm
  - metasystem
vendors:
  - Metasoft
products:
  - MetaCRM (up to 6.4.0 Beta06)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability was identified in Metasoft 美特软件 MetaCRM up to 6.4.0 Beta06. ... The attack may be launched remotely. The exploit is publicly available and might be used.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: ""
    evidence: Such manipulation of the argument File leads to unrestricted upload.
    confidence_band: high
cves:
  - id: CVE-2026-16324
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16324
rules:
  - title: Detect CVE-2026-16324 Exploitation - Metasoft MetaCRM Unrestricted Upload
    description: Detects exploitation attempts against Metasoft MetaCRM CVE-2026-16324, an unrestricted file upload vulnerability via POST requests to /business/qnaire/upload.jsp.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
---

The vulnerability, identified as CVE-2026-16324, affects Metasoft 美特软件 MetaCRM versions up to 6.4.0 Beta06. This flaw, classified as an unrestricted file upload, resides within an unknown function associated with the `/business/qnaire/upload.jsp` file. Attackers can remotely exploit this by manipulating the 'File' argument in an HTTP request, allowing arbitrary files, such as webshells, to be uploaded to the server. The public availability of an exploit significantly escalates the threat, as it enables adversaries to gain initial access, achieve persistent remote code execution, and potentially compromise the underlying system. Despite early disclosure, the vendor has not provided any response or patch, leaving affected organizations exposed to potential severe data breaches or system control loss.

## Attack Chain

1. **Reconnaissance & Vulnerability Identification**: An attacker identifies a Metasoft MetaCRM instance running a vulnerable version (up to 6.4.0 Beta06) that exposes the `/business/qnaire/upload.jsp` endpoint.
2. **Payload Preparation**: The attacker crafts a malicious file, such as a JSP webshell, designed to execute arbitrary commands on the server.
3. **Malicious File Upload**: The attacker sends a crafted HTTP POST request to the `/business/qnaire/upload.jsp` endpoint, manipulating the 'File' argument to include the malicious payload.
4. **Unrestricted Upload Exploitation**: The vulnerable MetaCRM application processes the request, failing to properly validate the uploaded file type or content, leading to the successful placement of the malicious file on the server.
5. **Webshell Deployment**: The uploaded malicious file (e.g., `shell.jsp`) is now accessible via a direct URL on the MetaCRM server.
6. **Remote Code Execution**: The attacker accesses the newly deployed webshell through a web browser or automated script, allowing them to execute arbitrary commands with the privileges of the web server process.
7. **Post-Exploitation**: With RCE, the attacker can establish persistence, exfiltrate sensitive data, move laterally within the network, or deploy further malicious payloads like ransomware.

## Impact

Successful exploitation of CVE-2026-16324 allows remote attackers to upload arbitrary files, including webshells, onto the MetaCRM server. This provides the attacker with immediate remote code execution capabilities, leading to complete compromise of the affected system. The potential damage includes unauthorized access to sensitive business data, alteration or deletion of critical information, system downtime, and the deployment of additional malware such as ransomware or cryptocurrency miners. The vulnerability carries a CVSS v3.1 Base Score of 7.3 (High), indicating significant impact on confidentiality, integrity, and availability, and the public availability of an exploit drastically increases the likelihood of attack.

## Recommendation

* **Patch**: Immediately apply any available patches or updates from Metasoft addressing CVE-2026-16324 to MetaCRM instances running versions up to 6.4.0 Beta06.
* **Deploy**: Deploy the Sigma rule "Detect CVE-2026-16324 Exploitation - Metasoft MetaCRM Unrestricted Upload" to your SIEM to detect attempts to exploit the `/business/qnaire/upload.jsp` endpoint.
* **Monitor**: Enhance monitoring of web server logs for the `webserver` logsource, specifically for HTTP POST requests to `/business/qnaire/upload.jsp` that might indicate anomalous file types or unusual query parameters.
* **Review**: Conduct a thorough review of the `/business/qnaire/upload.jsp` functionality in MetaCRM for proper input validation and file type restrictions.
