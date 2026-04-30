---
title: Shandong Hoteam InforCenter PLM Unrestricted Upload Vulnerability (CVE-2026-5261)
slug: 2026-04-hoteam-plm-upload
description: CVE-2026-5261 is an unrestricted file upload vulnerability in Shandong Hoteam InforCenter PLM up to version 8.3.8, allowing remote attackers to execute arbitrary code by uploading malicious files via the uploadFileToIIS function.
date: "2026-04-01T09:16:17Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - CVE-2026-5261
  - unrestricted-upload
  - hoteam-plm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2026-5261
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5261
  - https://vuldb.com/vuln/354450
rules:
  - title: Detect Suspicious PLM Uploads
    description: Detects suspicious POST requests to the uploadFileToIIS function in Hoteam PLM that might indicate an attempted exploit of CVE-2026-5261.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
      - T1190
    data_sources:
      - webserver
      - windows
  - title: Detect PLM Webshell Upload
    description: Detects web requests to webshells uploaded via CVE-2026-5261
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - windows
rules_count: 2
---

A critical vulnerability, CVE-2026-5261, has been identified in Shandong Hoteam InforCenter PLM software, specifically in versions up to 8.3.8. This vulnerability resides in the `uploadFileToIIS` function located within the `/Base/BaseHandler.ashx` file.  The vulnerability allows unauthenticated remote attackers to upload arbitrary files to the server due to a lack of proper input validation and access controls. The exploit is publicly available, increasing the risk of widespread exploitation. The vendor was notified but did not respond. This vulnerability poses a significant threat, as successful exploitation can lead to arbitrary code execution, data breaches, and complete system compromise.

## Attack Chain

1.  An attacker identifies a vulnerable Shandong Hoteam InforCenter PLM instance running version 8.3.8 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the `/Base/BaseHandler.ashx` endpoint, specifically invoking the `uploadFileToIIS` function.
3.  The attacker includes a `File` parameter in the request, containing a payload such as a webshell or other executable code disguised as a seemingly benign file type.
4.  Due to the unrestricted file upload vulnerability (CVE-2026-5261), the server accepts and stores the attacker's malicious file without proper validation.
5.  The attacker determines the final storage location of the uploaded file on the server's file system.
6.  The attacker crafts a new HTTP request to access the uploaded file, triggering its execution.
7.  The attacker gains a foothold on the server and can execute arbitrary commands.
8.  The attacker can then escalate privileges, move laterally within the network, exfiltrate sensitive data, or cause other damage to the system.

## Impact

Successful exploitation of CVE-2026-5261 allows a remote, unauthenticated attacker to upload arbitrary files to the vulnerable server. This can lead to arbitrary code execution and complete system compromise, potentially impacting all data and processes managed by the PLM software. There is currently no information about the number of affected systems or specific industries targeted, but the availability of a public exploit increases the potential for widespread attacks. Successful exploitation can result in data breaches, financial losses, and reputational damage.

## Recommendation

*   Apply available patches or upgrade to a secure version of Shandong Hoteam InforCenter PLM to remediate CVE-2026-5261.
*   Implement a web application firewall (WAF) rule to block requests with suspicious file extensions or content types being uploaded to `/Base/BaseHandler.ashx` to mitigate exploitation attempts.
*   Monitor web server logs for suspicious POST requests to `/Base/BaseHandler.ashx` with unusually large file sizes or unusual file extensions as indicated in the "Detect Suspicious PLM Uploads" Sigma rule.
*   Implement file integrity monitoring (FIM) on the web server's upload directories to detect unauthorized file creations or modifications to identify successful exploitation.
