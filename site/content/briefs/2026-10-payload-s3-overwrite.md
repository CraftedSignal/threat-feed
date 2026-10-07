---
title: Payload Storage-S3 Object Overwrite Vulnerability
slug: 2026-10-payload-s3-overwrite
description: An authenticated user can exploit a path configuration weakness in @payloadcms/storage-s3 to overwrite arbitrary S3 objects across collections, bypassing security controls.
date: "2026-10-07T22:50:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:payload:payloadcms_storage_s3:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - cloud
vendors:
  - Payload
products:
  - '@payloadcms/storage-s3 (< 3.90.0)'
  - '@payloadcms/storage-s3 (>= 4.0.0-canary.0, < 4.0.0-canary.34)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: An authenticated user could overwrite an existing S3 object belonging to another upload collection, bypassing that collection’s access controls and prior file validation.
    confidence_band: high
cves:
  - id: CVE-2026-105867
references:
  - https://github.com/advisories/GHSA-7vg8-29qx-jgj8
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105867
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade @payloadcms/storage-s3 to >= 3.90.0 or >= 4.0.0-canary.34
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-105867 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Disable client uploads until the package is updated
      owner: Application Security
      addresses: CVE-2026-105867
      evidence: Workaround provided in the advisory
---

The @payloadcms/storage-s3 package, used for managing file uploads in Payload CMS applications, contains a critical vulnerability (CVE-2026-105867) that allows authenticated users to perform unauthorized file operations. The issue exists when multiple upload collections share the same S3 bucket and the 'useCompositePrefixes' configuration setting is either disabled or missing. In this configuration, the storage driver fails to enforce isolation between different collections, permitting an attacker to craft upload requests that overwrite files belonging to other collections. This bypasses access controls and validation logic intended for the target collections. Organizations using Payload versions prior to 3.90.0 or the affected 4.0.0-canary range are exposed. Impact is restricted to environments where multiple collections share an S3 bucket with 'useCompositePrefixes' set to false.

## Impact

Successful exploitation results in the unauthorized modification or destruction of data within an S3 bucket. An attacker can overwrite existing files across different collections, effectively bypassing the security boundaries and validation checks defined for those specific collections. This can be used to replace legitimate application assets or configuration files with malicious content, leading to further compromise depending on how the application processes these files.

## Recommendation

* Immediately upgrade the @payloadcms/storage-s3 package to version 3.90.0 or later, or 4.0.0-canary.34 or later, to address CVE-2026-105867.
* If upgrading is not immediately possible, disable client-side file uploads as a temporary workaround.
* Audit S3 bucket configurations to verify if multiple collections share a single bucket and ensure 'useCompositePrefixes' is explicitly enabled in the Payload CMS storage configuration.
