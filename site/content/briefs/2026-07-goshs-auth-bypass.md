---
title: Goshs File-Based ACL Authorization Bypass via Bulk Zip Download
slug: 2026-07-goshs-auth-bypass
description: An unauthenticated attacker can exploit CVE-2026-54719 in goshs versions up to 1.1.4 and goshs/v2 up to 2.1.0 to bypass file-based Access Control Lists (ACLs) and read any file under the webroot using the `?bulk` zip-download route, leading to unauthorized information disclosure.
date: "2026-07-28T22:01:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - webserver
  - vulnerability
  - cve
  - information-disclosure
vendors:
  - patrickhener
products:
  - goshs (<= 1.1.4)
  - goshs/v2 (<= 2.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can therefore read any file under the webroot protected solely by a .goshs ACL, bypassing both the folder auth (401 on the normal path) and the per-file block list (404 on the normal path).
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: An unauthenticated attacker can therefore read any file under the webroot protected solely by a .goshs ACL
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1211
    technique_name: Exploitation for Defense Evasion
    evidence: An unauthenticated attacker can therefore read any file under the webroot protected solely by a .goshs ACL, bypassing both the folder auth (401 on the normal path) and the per-file block list (404 on the normal path).
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-rmxw-pq4x-3fvh
rules:
  - title: Detects CVE-2026-54719 Exploitation - Goshs bulk download ACL bypass
    description: Detects CVE-2026-54719 exploitation by identifying HTTP GET requests to the /?bulk endpoint with a file= parameter, indicating an attempt to bypass ACLs for unauthorized file download.
    platform: sigma
    severity: high
    tactics:
      - collection
      - defense_evasion
      - initial_access
    techniques:
      - T1005
      - T1190
      - T1211
    data_sources:
      - webserver
rules_count: 1
---

A high-severity authorization bypass vulnerability, tracked as CVE-2026-54719, has been identified in `goshs` (versions <= 1.1.4) and `goshs/v2` (versions <= 2.1.0) which allows unauthenticated attackers to read arbitrary files. This flaw is a residual vulnerability from a previous fix (GHSA-wvhv-qcqf-f3cx) which addressed ACL bypasses on state-changing routes but failed to cover the `?bulk` zip-download endpoint. The `bulkDownload` function, invoked by requests containing `?bulk` and `?file=` parameters, retrieves file contents as a ZIP archive without performing the necessary `.goshs` ACL checks or honoring per-file block lists. This critical oversight enables any unauthenticated network attacker to bypass folder-level and file-level access controls, leading to unauthorized disclosure of confidential information from files located under the webroot. The vulnerability does not affect write or delete operations, limiting the impact to confidentiality only.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable `goshs` instance exposed on the network.
2. The attacker attempts to access a known protected file directly (e.g., `GET /protected/secret.txt`), which is correctly denied with a 401 Unauthorized response by the server's standard authorization flow.
3. The attacker then crafts a malicious HTTP GET request targeting the `?bulk` zip-download route, appending the `?file=` parameter with the path to the desired protected file (e.g., `GET /?bulk&file=/protected/secret.txt`).
4. The `goshs` server receives this request and routes it to the `bulkDownload` function, bypassing the normal authorization gates.
5. The `bulkDownload` function processes the `?file=` parameter, retrieves the content of `/protected/secret.txt`, and streams it back to the attacker within a ZIP archive.
6. The attacker extracts the ZIP archive to obtain the contents of the confidential file, completely circumventing the `.goshs` ACL protections and any per-file block lists.

## Impact

Successful exploitation of CVE-2026-54719 leads to unauthorized information disclosure, specifically the confidentiality of any file stored under the `goshs` webroot that relies solely on `.goshs` ACLs for protection. While a server-wide basic authentication mechanism (`-b` flag) would still gate the `?bulk` route, deployments relying on per-folder `.goshs` ACLs are vulnerable. Attackers can exfiltrate sensitive data such as configuration files, user data, or intellectual property without any authentication, posing a significant risk to data privacy and security. The vulnerability does not allow for data modification or deletion.

## Recommendation

* Deploy the Sigma rule `Detects CVE-2026-54719 Exploitation - Goshs bulk download ACL bypass` to your SIEM to identify attempts to exploit this vulnerability.
* Monitor web server access logs for `GET` requests to `/?bulk` containing the `file=` parameter, as these indicate potential exploitation attempts.
* Apply the latest security patches from `goshs` developers immediately, which should enforce `.goshs` ACLs within the `bulkDownload` function or route `?bulk` requests through the same authorization gate as normal read paths.
* Conduct an audit of other alternate read routes such as `?cbDown` within your `goshs` deployments for similar authorization bypass gaps.
