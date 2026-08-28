---
title: Broken Access Control in Snipe-IT Asset Maintenance API
slug: 2026-08-snipe-it-auth-bypass
description: An authenticated user in a multi-company Snipe-IT deployment can exploit an authorization flaw in the asset maintenance update API to re-parent records to assets owned by other companies, breaking tenant isolation.
date: "2026-08-28T21:17:48Z"
lastmod: "2026-08-28T21:18:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:snipeitapp:snipe-it:*:*:*:*:*:*:*:*
tags:
  - web-application
  - privilege-escalation
  - multi-tenant
  - web-application-vulnerability
  - path-traversal
  - cve-2026-55474
  - authorization-bypass
vendors:
  - Snipe-IT
products:
  - Snipe-IT (<= 8.6.1)
  - Snipe-IT (< 8.5.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'The update method loads the maintenance, checks access to the existing $maintenance->asset, then calls: $maintenance->fill($request->all()); $maintenance->save();'
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The filename parameter from the HTTP route is concatenated directly into a filesystem path with no sanitization, allowing an authenticated attacker to traverse outside the intended directory and read arbitrary files.
    confidence_band: high
cves:
  - id: CVE-2026-55516
    cvss: 7.7
    epss: 0.00376
references:
  - https://github.com/advisories/GHSA-575r-357h-fhch
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55516
  - https://github.com/advisories/GHSA-c6f4-wj38-m3g3
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55474
  - https://github.com/advisories/GHSA-vgx7-c78r-69w9
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55460
rules:
  - title: Detects CVE-2026-55474 Exploitation - Path Traversal in displaySig
    description: Detects HTTP requests to the displaySig endpoint containing directory traversal patterns in the filename parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1083
    data_sources:
      - webserver
  - title: Detect CVE-2026-55460 Exploitation - Unauthorized Bulk User Deletion
    description: Detects unauthorized attempts to invoke the bulk user deletion functionality by non-privileged users via the /users/bulksave endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Snipe-IT to 8.6.2 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-55516
  mitigation_plan:
    - priority: immediate
      action: Monitor API access logs for anomalous PATCH/PUT requests to maintenance endpoints.
      owner: SOC
      addresses: CVE-2026-55516
      evidence: Affected endpoint documentation
updates:
  - at: "2026-08-28T21:18:06Z"
    level: L1
    summary: 'added detection rule: Detects CVE-2026-55474 Exploitation - Path Traversal in displaySig'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-c6f4-wj38-m3g3
  - at: "2026-08-28T21:18:14Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-55460 Exploitation - Unauthorized Bulk User Deletion'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-vgx7-c78r-69w9
---

Snipe-IT version 8.6.1 and earlier is vulnerable to a broken access control flaw identified as CVE-2026-55516. The vulnerability exists within the API endpoints used to update maintenance records, specifically `PATCH /api/v1/maintenances/{maintenance_id}` and `PUT /api/v1/maintenances/{maintenance_id}`. 

In a multi-company environment where strict tenant isolation is expected, the application correctly validates access to the existing maintenance record and its associated asset during the update process. However, it fails to perform secondary authorization checks on the newly supplied `asset_id` provided in the request body. This allows an authenticated user with maintenance modification permissions to re-parent a maintenance record to an asset belonging to a different company to which they should not have access. This flaw compromises the integrity of asset lifecycle records and enables unauthorized cross-company modification.

## Attack Chain

1. Attacker authenticates to the Snipe-IT web application using a legitimate API token with maintenance management permissions.
2. Attacker retrieves or identifies a `maintenance_id` currently associated with an asset within their authorized company scope.
3. Attacker identifies the `asset_id` of a victim asset belonging to a different company (the target).
4. Attacker constructs a `PATCH` or `PUT` request to `/api/v1/maintenances/{maintenance_id}`.
5. Attacker includes the target `asset_id` in the request body JSON payload.
6. The `MaintenancesController` validates access to the initial asset but fails to validate the new `asset_id` against the user's company scope.
7. The application executes `$maintenance->save()`, committing the unauthorized association to the database.
8. The victim company's asset records are now polluted with the attacker-controlled maintenance entry.

## Impact

The vulnerability results in a loss of data integrity for multi-company deployments by bypassing tenant isolation. Attackers can pollute asset history across company boundaries, leading to incorrect warranty, audit, and maintenance tracking. This may also be used to obfuscate asset history or generate fraudulent maintenance records for assets owned by other entities within the same Snipe-IT instance.

## Recommendation

1. Upgrade to a version of Snipe-IT that resolves CVE-2026-55516.
2. Review application logs for API calls to `MaintenancesController` originating from low-privilege accounts that involve `asset_id` changes to determine if cross-company record movement has occurred.
3. If immediate patching is not possible, restrict API access for non-administrative accounts until a fix is deployed.
