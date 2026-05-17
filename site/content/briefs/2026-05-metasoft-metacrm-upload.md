---
title: Metasoft MetaCRM Unrestricted File Upload Vulnerability (CVE-2026-8758)
slug: 2026-05-metasoft-metacrm-upload
description: A vulnerability in Metasoft MetaCRM up to version 6.4.0 Beta06 allows for unrestricted file upload due to manipulation of the 'File' argument in the /common/jsp/upload3.jsp file, potentially leading to arbitrary code execution.
date: "2026-05-17T14:18:11Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - unrestricted-upload
  - rce
  - web-application
vendors:
  - Metasoft 美特软件
products:
  - MetaCRM (<= 6.4.0 Beta06)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-8758
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8758
  - https://ucn9h68n9289.feishu.cn/wiki/XmoNwpJjJiQrBtkLMitccF56ntb
  - https://vuldb.com/submit/811283
  - https://vuldb.com/vuln/364385
  - https://vuldb.com/vuln/364385/cti
rules:
  - title: Detects CVE-2026-8758 Exploitation — MetaCRM Unrestricted Upload Attempt
    description: Detects CVE-2026-8758 exploitation — Attempts to upload files to /common/jsp/upload3.jsp in MetaCRM that may indicate an unrestricted upload vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detects CVE-2026-8758 Exploitation — MetaCRM Suspicious File Extension Upload
    description: Detects CVE-2026-8758 exploitation — Detects uploads of common web server script extensions to the MetaCRM application, which may lead to remote code execution.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

Metasoft 美特软件 MetaCRM, a customer relationship management system, is vulnerable to an unrestricted file upload vulnerability (CVE-2026-8758) affecting versions up to 6.4.0 Beta06. The vulnerability resides in the `/common/jsp/upload3.jsp` file, and successful exploitation allows an unauthenticated attacker to upload arbitrary files to the server. Publicly available exploits exist, increasing the risk of active exploitation. The vendor was notified but did not respond. This vulnerability can lead to arbitrary code execution, data breaches, and full system compromise.

## Attack Chain

1.  The attacker identifies a MetaCRM instance running a vulnerable version (<= 6.4.0 Beta06).
2.  The attacker crafts a malicious HTTP POST request targeting the `/common/jsp/upload3.jsp` endpoint.
3.  The attacker manipulates the `File` argument within the request, potentially using techniques to bypass file type restrictions (e.g., double extensions, null byte injection).
4.  The server processes the request without proper validation, allowing the attacker to upload a file containing malicious code (e.g., a JSP webshell).
5.  The attacker accesses the uploaded file via a direct HTTP request to its location on the server.
6.  The server executes the malicious code within the uploaded file, granting the attacker arbitrary code execution.
7.  The attacker establishes persistence by, for example, writing a startup script or modifying system configuration files.

## Impact

Successful exploitation of CVE-2026-8758 allows an unauthenticated remote attacker to upload arbitrary files, leading to arbitrary code execution on the affected MetaCRM server. This can result in complete system compromise, data breaches, and denial of service. Given that CRM systems often contain sensitive customer data, a successful attack could have significant financial and reputational consequences.

## Recommendation

*   Upgrade to a patched version of MetaCRM that addresses CVE-2026-8758; apply available patches immediately to MetaCRM instances.
*   Deploy the Sigma rule provided below to detect exploitation attempts against `/common/jsp/upload3.jsp`.
*   Implement file upload restrictions and validation on the server side to prevent the upload of malicious file types.
*   Monitor web server logs for suspicious activity, including requests to `/common/jsp/upload3.jsp` with unusual parameters.
*   Implement network segmentation to limit the impact of a successful compromise on other systems.
*   Review and enforce principle of least privilege on the MetaCRM system, restricting file upload access to authorized users only.
