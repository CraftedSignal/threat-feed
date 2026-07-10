---
title: Directus File Overwrite Vulnerability (CVE-2026-39942)
slug: 2024-01-directus-file-overwrite
description: A file overwrite vulnerability (CVE-2026-39942) exists in Directus versions prior to 11.17.0, where an attacker can overwrite another user's files by manipulating the filename_disk parameter in the PATCH /files/{id} endpoint, potentially leading to data corruption or privilege escalation.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - directus
  - file-overwrite
  - privilege-escalation
  - CVE-2026-39942
vendors:
  - Directus
products:
  - Directus
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
cves:
  - id: CVE-2026-39942
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39942
rules:
  - title: Detect Directus File Overwrite Attempt via PATCH Request
    description: Detects potential exploitation of the Directus file overwrite vulnerability (CVE-2026-39942) by monitoring PATCH requests to the /files endpoint with suspicious filename_disk parameters.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Directus Suspicious Metadata Manipulation
    description: Detects suspicious manipulation of metadata fields (e.g., uploaded_by) in Directus PATCH requests, potentially indicating an attempt to obscure file overwrites.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Directus is a real-time API and App dashboard used for managing SQL database content. A vulnerability, identified as CVE-2026-39942, affects versions of Directus prior to 11.17.0. The vulnerability lies in the PATCH /files/{id} endpoint, which improperly handles the filename_disk parameter. A malicious actor can exploit this by crafting a request that sets the filename_disk parameter to the storage path of another user's file. Successful exploitation allows the attacker to overwrite the targeted file's content, potentially corrupting data or gaining unauthorized access. Additionally, the attacker can manipulate metadata fields like uploaded_by to obscure the tampering, making detection more challenging. Upgrading to version 11.17.0 or later resolves this vulnerability.

## Attack Chain

1.  Attacker identifies a vulnerable Directus instance running a version prior to 11.17.0.
2.  Attacker authenticates to the Directus instance with a valid user account.
3.  Attacker identifies the target file's storage path on the disk. This might involve enumeration or prior knowledge of the file system structure.
4.  Attacker crafts a malicious PATCH request to the /files/{id} endpoint, where {id} is the ID of a file they control.
5.  In the PATCH request body, the attacker sets the filename_disk parameter to the storage path of the target file they wish to overwrite.
6.  The attacker also manipulates other metadata fields, such as uploaded_by, to disguise their actions in audit logs.
7.  The Directus server processes the PATCH request, overwriting the content of the target file with the attacker's controlled data.
8.  The attacker achieves the objective of overwriting the target file, potentially leading to data corruption, privilege escalation (if the overwritten file is an executable or configuration file), or defacement.

## Impact

Successful exploitation of CVE-2026-39942 allows an attacker to overwrite arbitrary files within the Directus instance's storage directory. This could lead to data corruption, where legitimate files are replaced with malicious content. If the overwritten file is an executable or configuration file, the attacker could potentially achieve privilege escalation, allowing them to gain control of the Directus instance or the underlying server. Furthermore, the attacker's ability to manipulate metadata fields makes it difficult to trace the malicious activity, hindering incident response efforts. The number of potential victims depends on the prevalence of vulnerable Directus instances.

## Recommendation

*   Immediately upgrade Directus to version 11.17.0 or later to patch CVE-2026-39942.
*   Implement the Sigma rule "Detect Directus File Overwrite Attempt via PATCH Request" to detect attempts to exploit this vulnerability by monitoring PATCH requests to the /files endpoint with suspicious filename_disk parameters.
*   Monitor web server logs for PATCH requests to the /files endpoint (webserver logs) with unusual filename_disk values that deviate from expected patterns.
