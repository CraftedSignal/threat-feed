---
title: Information Disclosure and Unauthorized File Deletion in PictShare
slug: 2026-10-pictshare-info-disclosure
description: PictShare versions prior to 3.7.1 are vulnerable to an unauthenticated information disclosure flaw in the API::info() endpoint, allowing attackers to retrieve sensitive metadata and delete arbitrary files.
date: "2026-10-01T22:18:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pictshare:pictshare:*:*:*:*:*:*:*:*
tags:
  - information-disclosure
  - api-vulnerability
  - cve-2026-104051
vendors:
  - PictShare
products:
  - PictShare (< 3.7.1)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: The endpoint fails to implement a field whitelist, allowing unauthenticated attackers to retrieve sensitive metadata.
    confidence_band: high
cves:
  - id: CVE-2026-104051
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104051
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade PictShare to 3.7.1 or later to remediate CVE-2026-104051.
      owner: IT Operations
      due: 48h
      evidence: Source states PictShare before 3.7.1 contains an information disclosure vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade PictShare to version 3.7.1.
      owner: IT Operations
      addresses: CVE-2026-104051
      evidence: NVD vulnerability details identify 3.7.1 as the fixed version.
---

PictShare versions prior to 3.7.1 contain an information disclosure vulnerability in the API::info() endpoint. The application fails to implement a field whitelist when returning metadata objects via this API. As a result, unauthenticated attackers can supply a file hash to the endpoint to retrieve the complete metadata object. This object contains highly sensitive information, including the secret 'delete_code', the original uploader's IP address, User Agent string, remote port, and the file's SHA-1 hash. The exposure of the 'delete_code' presents a significant security risk, as an attacker can use this value to invoke the application's delete API to permanently remove arbitrary files from the server, leading to a loss of data integrity and system availability. Defenders should prioritize patching this vulnerability by upgrading to version 3.7.1 or later.

## Attack Chain

1. Attacker identifies a target PictShare instance accessible over the network.
2. Attacker gathers publicly accessible file hashes from the application's front-end or through reconnaissance.
3. Attacker sends a crafted HTTP GET or POST request to the API::info() endpoint, including a target file hash in the request parameters.
4. The application processes the request and returns the full, unfiltered metadata object associated with the hash to the unauthenticated attacker.
5. Attacker parses the JSON or raw response to extract the 'delete_code' and sensitive uploader metadata (IP, User Agent).
6. Attacker sends a secondary request to the application's delete API endpoint, providing the extracted 'delete_code'.
7. The application validates the 'delete_code' and proceeds to permanently delete the requested file.
8. Successful deletion results in a permanent loss of content availability and potential privacy impact for the original uploader.

## Impact

Successful exploitation results in unauthorized information disclosure of user metadata and the ability for unauthenticated attackers to perform arbitrary file deletions. This compromises both user privacy and the availability of data hosted on the affected PictShare instance. The vulnerability carries a CVSS v3.1 base score of 8.2, reflecting its severity in environments where data availability is critical.

## Recommendation

1. Upgrade all PictShare instances to version 3.7.1 or later immediately to address CVE-2026-104051.
2. Implement network-level access controls to restrict exposure of the PictShare API endpoints to untrusted networks.
3. Review web server logs for high volumes of requests to the API::info() endpoint followed by requests to the delete API, which may indicate exploitation attempts.
