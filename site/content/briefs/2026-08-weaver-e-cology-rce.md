---
title: Unauthenticated Remote Code Execution in Weaver E-cology 9.0
slug: 2026-08-weaver-e-cology-rce
description: Weaver E-cology 9.0 versions prior to 10.52 are vulnerable to unauthenticated arbitrary file upload via the /workrelate/plan/util/uploaderOperate.jsp endpoint, allowing remote code execution.
date: "2026-08-07T15:33:27Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - vulnerability
  - rce
  - file-upload
  - webserver
vendors:
  - Weaver
products:
  - E-cology 9.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Weaver (Fanwei) E-cology 9.0 versions prior to 10.52 contain a file upload vulnerability that allows a remote, unauthenticated attacker to upload arbitrary files, including JSP webshells.
    confidence_band: high
cves:
  - id: CVE-2022-4995
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-4995
rules:
  - title: Detects CVE-2022-4995 Exploitation - Arbitrary JSP File Upload Attempt
    description: Detects unauthenticated POST requests to the vulnerable uploaderOperate.jsp endpoint which is indicative of attempts to upload webshells.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

Weaver (Fanwei) E-cology 9.0 versions prior to 10.52 contain a critical arbitrary file upload vulnerability (CVE-2022-4995) that enables remote, unauthenticated attackers to gain remote code execution (RCE). The vulnerability exists within the /workrelate/plan/util/uploaderOperate.jsp endpoint, which fails to properly validate incoming file uploads. By sending a crafted multipart/form-data POST request containing arbitrary secId and plandetailid parameters, an attacker can upload malicious JSP files to the web server. Once the file is written to the application's accessible web root, the attacker can execute arbitrary commands under the context of the application server process. This vulnerability has been subject to active exploitation in the wild since at least October 14, 2023.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing Weaver E-cology 9.0 instances.
2. Attacker crafts a multipart/form-data HTTP POST request targeting /workrelate/plan/util/uploaderOperate.jsp.
3. Attacker injects a malicious JSP webshell into the body of the multipart request.
4. Attacker includes arbitrary values in the secId and plandetailid fields to bypass application-level checks.
5. The vulnerable server accepts the request and writes the JSP file to an accessible directory.
6. Attacker sends a GET request to the newly uploaded JSP file path to trigger code execution.
7. The application server process executes the embedded commands, granting the attacker RCE.

## Impact

Successful exploitation of CVE-2022-4995 results in full remote code execution, allowing attackers to compromise the application server. This can lead to total system takeover, data exfiltration, and potential lateral movement within the affected organization. Given the nature of the application, these servers often house sensitive corporate documents and internal project planning data.

## Recommendation

1. Upgrade all Weaver E-cology 9.0 instances to version 10.52 or later to mitigate CVE-2022-4995.
2. Deploy the Sigma rule below to monitor for exploitation attempts targeting the identified JSP upload endpoint.
3. Implement strict access control lists (ACLs) to restrict access to /workrelate/plan/util/uploaderOperate.jsp to trusted internal IP addresses only.
4. Audit the web root directory for suspicious JSP files created after October 2023.
