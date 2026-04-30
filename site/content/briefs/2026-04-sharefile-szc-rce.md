---
title: ShareFile Storage Zones Controller Unauthenticated Configuration Access and Potential RCE (CVE-2026-2699)
slug: 2026-04-sharefile-szc-rce
description: An unauthenticated attacker can access restricted configuration pages in Customer Managed ShareFile Storage Zones Controller (SZC), leading to system configuration changes and potential remote code execution.
date: "2026-04-02T14:16:27Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - sharefile
  - storage-zones-controller
  - rce
  - cve-2026-2699
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1020
    technique_name: Automated Execution
references:
  - https://docs.sharefile.com/en-us/storage-zones-controller/5-0/security-vulnerability-feb26
  - https://github.com/watchtowrlabs/watchTowr-vs-Progress-ShareFile-CVE-2026-2699
iocs:
  - type: url
    value: https://docs.sharefile.com/en-us/storage-zones-controller/5-0/security-vulnerability-feb26
  - type: url
    value: https://github.com/watchtowrlabs/watchTowr-vs-Progress-ShareFile-CVE-2026-2699
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect Unauthorized Access to ShareFile SZC Configuration Pages
    description: Detects attempts to access restricted configuration pages in ShareFile Storage Zones Controller without authentication.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
  - title: Detect Suspicious File Uploads to ShareFile SZC
    description: Detects file uploads to ShareFile Storage Zones Controller that may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1020
    data_sources:
      - webserver
      - windows
rules_count: 2
---

CVE-2026-2699 affects Customer Managed ShareFile Storage Zones Controller (SZC) versions prior to the fix. The vulnerability allows an unauthenticated attacker to bypass access controls and directly access restricted configuration pages. This unauthorized access can lead to malicious actors changing system settings, potentially installing backdoors, or executing arbitrary code remotely. The vulnerability was reported to Progress Software Corporation and assigned a CVSS v3.1 base score of 9.8, categorizing it as critical. Successful exploitation of this vulnerability could have significant consequences for organizations using the affected ShareFile SZC, as it could compromise sensitive data and system integrity. Defenders should prioritize patching and detection efforts to mitigate this risk.

## Attack Chain

1.  The attacker identifies a vulnerable ShareFile Storage Zones Controller (SZC) instance.
2.  The attacker crafts a malicious HTTP request targeting a restricted configuration page, bypassing authentication checks.
3.  The SZC processes the request without proper authorization, granting access to the restricted page.
4.  The attacker modifies critical system configurations, potentially including settings related to file storage, authentication, or update mechanisms.
5.  The attacker leverages the modified configurations to upload a malicious file to the SZC.
6.  The uploaded file, potentially a script or executable, is then executed by the SZC.
7.  The attacker achieves remote code execution, gaining control over the SZC server.
8.  The attacker uses the compromised SZC to access sensitive data or pivot to other systems within the network.

## Impact

Successful exploitation of CVE-2026-2699 can result in complete compromise of the ShareFile Storage Zones Controller (SZC) instance. This can lead to unauthorized access to sensitive data stored within the ShareFile environment. Attackers can also use the compromised SZC as a pivot point to access other internal systems. The affected sectors could include any organization using the vulnerable ShareFile SZC setup, potentially leading to widespread data breaches and operational disruption. Given the CVSS score of 9.8, the impact is considered critical.

## Recommendation

*   Immediately patch all Customer Managed ShareFile Storage Zones Controller (SZC) instances to the latest version as recommended in the Progress Software Corporation advisory referenced in the documentation URL within the IOCs section.
*   Deploy the Sigma rule to detect unauthorized access attempts to restricted configuration pages on ShareFile SZC servers, monitoring webserver logs for suspicious activity.
*   Review network traffic for unusual outbound connections from ShareFile SZC servers after the patch, looking for signs of potential compromise, based on network connection logs.
*   Monitor ShareFile SZC server logs for any unauthorized configuration changes based on file event logs after patching.
