---
title: Path Traversal Vulnerability in Pulpcore (CVE-2026-12701)
slug: 2026-07-path-traversal-pulpcore
description: An authenticated administrator can exploit a path traversal vulnerability in the 'relative_path_validator' function within 'pulpcore'. During 'FilesystemExport' operations, specially crafted 'relative_path' values containing directory traversal sequences (e.g., "../") can bypass validation, leading to arbitrary file writes. This allows an attacker to write files to any location writable by the Pulp service user, such as '/etc/shadow', potentially leading to service compromise, privilege escalation, or further system exploitation.
date: "2026-07-20T15:17:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - vulnerability
  - linux
  - pulpcore
vendors:
  - Pulp
products:
  - pulpcore
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: allows arbitrary file write to any location writable by the Pulp service user, such as '/etc/shadow'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: potentially leading to service compromise or further system exploitation
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: arbitrary file write... potentially leading to service compromise or further system exploitation
    confidence_band: med
cves:
  - id: CVE-2026-12701
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12701
---

A critical path traversal vulnerability, identified as CVE-2026-12701, has been discovered in Pulpcore, a component of the Pulp content management platform. The vulnerability resides in the `relative_path_validator` function, which, while designed to prevent content paths from starting with a slash (`/`), fails to adequately block directory traversal sequences such as `../` when embedded deeper within a path. This flaw allows an authenticated administrator to craft a malicious `relative_path` during `FilesystemExport` operations. By injecting traversal sequences (e.g., "looking/normal/../../../../etc/shadow"), an attacker can escape the intended export directory. Coupled with the ability to upload user-controlled file content (artifacts), this vulnerability facilitates arbitrary file write to any location on the system writable by the Pulp service user. Successful exploitation could lead to service compromise, privilege escalation, or further system exploitation, making it a severe risk for affected organizations.

## Attack Chain

1. **Initial Access**: An attacker obtains or already possesses authenticated administrator credentials for a Pulpcore instance.
2. **Prepare Malicious Content**: The attacker prepares a malicious artifact (e.g., a web shell, a script, or a modified system configuration file like `/etc/shadow`) and uploads it to Pulpcore.
3. **Initiate Export Operation**: The attacker initiates a `FilesystemExport` operation through the Pulpcore API or user interface.
4. **Craft Traversal Path**: The attacker crafts a `relative_path` parameter for the export containing directory traversal sequences, such as `looking/normal/../../../../etc/shadow`, designed to escape the default export directory.
5. **Bypass Validation**: The vulnerable `relative_path_validator` function in Pulpcore processes the crafted path, but due to its flawed logic, it fails to identify and block the embedded `../` sequences.
6. **Arbitrary File Write**: Pulpcore proceeds to write the previously uploaded malicious artifact to the arbitrary location specified by the attacker's crafted `relative_path`, leveraging the privileges of the Pulp service user.
7. **Achieve System Compromise**: The successful arbitrary file write allows the attacker to modify critical system files (like `/etc/shadow` for privilege escalation) or establish persistence mechanisms, leading to service compromise or further system exploitation.

## Impact

A successful exploitation of CVE-2026-12701 results in arbitrary file write capabilities on the system running Pulpcore. This directly allows an attacker to overwrite or create files in sensitive locations, such as `/etc/shadow` for modifying user accounts or gaining root access, or injecting malicious scripts for persistence. The immediate impact is service compromise, but it can quickly escalate to full system takeover, unauthorized data access, or the deployment of additional malicious payloads. The vulnerability has a CVSS v3.1 base score of 9.0, indicating critical severity and a high potential for devastating impact on the confidentiality, integrity, and availability of affected systems.

## Recommendation

* Patch CVE-2026-12701 by updating Pulpcore to the latest security-hardened version immediately to remediate the path traversal vulnerability.
* Review server and application logs for the Pulp service user for any unusual file write activities, especially to sensitive system directories such as `/etc`, `/var`, or `/usr/local`.
* Monitor web server logs (e.g., Apache, Nginx) for the Pulpcore application for `FilesystemExport` operations or similar API calls that include suspicious `relative_path` parameters containing directory traversal sequences like `../` or their URL-encoded equivalents.
