---
title: Authenticated Sharp Users Can Download Unrelated Laravel Storage Objects
slug: 2026-05-sharp-laravel-storage-disclosure
description: An authenticated Sharp user with view access to at least one valid Sharp entity instance can download unrelated files from configured Laravel Storage disks by manipulating the `disk` and `path` parameters in the generic download endpoint, potentially exposing sensitive data like backups and internal documents; this vulnerability is tracked as CVE-2026-44692.
date: "2026-05-15T18:03:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authenticated-disclosure
  - web-application
  - laravel
  - sharp
vendors:
  - Laravel
products:
  - composer/code16/sharp
  - Laravel Storage
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-748w-hm6r-qc7v
  - https://laravel.com/docs/urls#signed-urls
  - https://cwe.mitre.org/data/definitions/639.html
rules:
  - title: Detect Sharp Laravel Storage Download Endpoint Abuse
    description: Detects CVE-2026-44692 exploitation — suspicious requests to the Sharp download endpoint with unusual disk or path parameters, indicating potential unauthorized access to Laravel Storage files.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Sharp Laravel Storage Download Endpoint Without Signature
    description: Detects requests to Sharp Laravel Storage download endpoint without a signature, indicating potential bypass of intended access controls.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The Sharp package for Laravel exposes a generic download endpoint that improperly authorizes access to storage objects. An authenticated user who has access to at least one valid Sharp entity instance can exploit this vulnerability (CVE-2026-44692) to download unrelated files from Laravel Storage disks. The application authorizes based on the Sharp entity instance, but then reads the storage `disk` and `path` directly from the request parameters, meaning there's no binding between the authorized entity and the requested storage object. This allows attackers to bypass intended access controls and potentially access sensitive files stored on configured Laravel Storage disks. Successful exploitation requires a valid Sharp session and view access to one valid entity. Versions prior to 9.22.0 are affected.

## Attack Chain

1. Attacker authenticates to the Sharp application with valid credentials.
2. Attacker identifies a valid Sharp entity instance to which they have view access.
3. Attacker crafts a request to the `/sharp/{globalFilter}/download/{entityKey}/{instanceId?}` endpoint.
4. The attacker modifies the `disk` and `path` parameters in the request to point to a different file within the configured Laravel Storage disks.
5. The application authorizes the request based on the valid Sharp entity instance, but doesn't validate the requested `disk` or `path` against that instance.
6. The application retrieves the file specified by the manipulated `disk` and `path` parameters from the Laravel Storage disk.
7. The application sends the contents of the unrelated file to the attacker.
8. The attacker gains unauthorized access to potentially sensitive information, such as backups, invoices, or internal documents.

## Impact

Successful exploitation of CVE-2026-44692 can lead to the authenticated disclosure of unrelated objects from configured Laravel Storage disks. Exposed files may include exports, backups, invoices, internal documents, uploads belonging to other records, tenant-specific data, or operational files stored on private application disks. The severity of the impact depends on the sensitivity of the data stored on the affected Laravel Storage disks.

## Recommendation

*   Upgrade to composer/code16/sharp version 9.22.0 or later, which includes a fix for CVE-2026-44692.
*   Restrict `downloads.allowed_disks` to the smallest possible set of disks required by Sharp downloads, as mentioned in the advisory.
*   Deploy the Sigma rule "Detect Sharp Laravel Storage Download Endpoint Abuse" to identify requests that may be exploiting this vulnerability.
*   Monitor web server logs for requests to the `/sharp/{globalFilter}/download/{entityKey}/{instanceId?}` endpoint where the `disk` or `path` parameters deviate significantly from expected values.
