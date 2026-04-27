---
title: Shandong Hoteam InforCenter PLM Unrestricted Upload Vulnerability (CVE-2026-5261)
slug: 2026-04-hoteam-plm-upload
description: CVE-2026-5261 is an unrestricted file upload vulnerability in Shandong Hoteam InforCenter PLM up to version 8.3.8, allowing remote attackers to execute arbitrary code by uploading malicious files via the uploadFileToIIS function.
date: "2026-04-01T09:16:17Z"
severities:
  - critical
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

A critical vulnerability, CVE-2026-5261, has been identified in Shandong Hoteam InforCenter PLM software, specifically in versions up to 8.3.8. This vulnerability resides in the `uploadFileToIIS` function located within the `/Base/BaseHandler.ashx` file.  The vulnerability allows unauthenticated remote attackers to upload arbitrary files to the server due to a lack of proper input validation and access controls. The exploit is publicly available, increasing the risk of widespread exploitation…
