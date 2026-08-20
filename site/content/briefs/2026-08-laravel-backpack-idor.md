---
title: Arbitrary File Deletion in Backpack for Laravel
slug: 2026-08-laravel-backpack-idor
description: An insecure direct object reference vulnerability in the HasUploadFields trait of Backpack for Laravel allows authenticated users to delete arbitrary files on the configured storage disk via manipulated request parameters.
date: "2026-08-20T19:13:48Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Backpack for Laravel
products:
  - Backpack CRUD (5.x, 6.x < 6.8.12, 7.x < 7.0.35)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565.002
    technique_name: Data Destruction
    evidence: An attacker... can supply arbitrary disk-relative paths in clear_<attr>[] to delete files that were never associated with the record they are editing.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8xjm-wqrp-2f25
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54178
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade backpack/crud to patched versions (6.8.12 or 7.0.35)
      owner: IT Operations
      due: 24h
      evidence: Fixed in 6.8.12 and 7.0.35
  mitigation_plan:
    - priority: immediate
      action: Migrate legacy upload patterns to Uploader API
      owner: Security Engineering
      addresses: CVE-2026-54178
      evidence: Deployments still using the uploadMultipleFilesToDisk mutator pattern should migrate to the Uploader API
---

Backpack for Laravel contains a high-severity insecure direct object reference (IDOR) vulnerability, tracked as CVE-2026-54178, affecting the `HasUploadFields::uploadMultipleFilesToDisk` method. This method, utilized primarily in v5.x implementations and supported in subsequent versions for backward compatibility, processes file deletion requests from the `clear_<attribute>[]` input parameter without verifying that the requested file paths are associated with the record currently being modified. 

An authenticated user with sufficient permissions to update CRUD models can supply arbitrary, disk-relative paths within this request parameter, forcing the application to delete files that were never associated with their account or the specific record. This vulnerability bypasses authorization logic, allowing for widespread file deletion, which can result in significant service disruption or data loss. The issue is resolved by implementing file path intersection logic, which ensures only existing model-associated files are targeted for deletion. Users are encouraged to migrate to the modern Uploader API to mitigate this risk.

## Impact

Successful exploitation allows a low-privilege attacker (e.g., a content editor) to delete any file residing on the application's configured storage disk. This impacts the integrity and availability of shared assets, application attachments, and operational files. There is no associated confidentiality impact, as the vulnerability does not permit the reading of file contents. Affected environments include all 5.x releases, 6.x versions prior to 6.8.12, and 7.x versions prior to 7.0.35.

## Recommendation

- Upgrade the `backpack/crud` package to version 6.8.12, 7.0.35, or higher to apply the security fix.
- Migrate all legacy `uploadMultipleFilesToDisk` model mutator patterns to the new Uploader API (`MultipleFiles` class) as defined in the Backpack documentation.
- Audit storage disk access logs for anomalous, high-frequency deletion requests originating from administrative endpoints.
- Restrict administrative access to CRUD operations to trusted users only to minimize the risk of malicious file deletion.
