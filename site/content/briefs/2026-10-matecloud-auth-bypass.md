---
title: Authorization Bypass in MateCloud StorageController
slug: 2026-10-matecloud-auth-bypass
description: MateCloud versions 5.0.8 and earlier contain an authorization bypass vulnerability (CVE-2026-110108) allowing authenticated users to perform unauthorized administrative object storage operations.
date: "2026-10-13T18:37:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:matecloud:matecloud:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - web-application
  - storage-security
vendors:
  - MateCloud
products:
  - MateCloud (<= 5.0.8)
cves:
  - id: CVE-2026-110108
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110108
rules:
  - title: Detects CVE-2026-110108 Exploitation - Unauthorized Access to Storage API
    description: Detects unauthorized access attempts to the administrative storage API endpoints exposed by CVE-2026-110108.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Monitor web logs for /api/v1/admin/storage path access
      owner: SOC
      due: 24h
      evidence: Source explicitly names the vulnerable endpoint path
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to administrative API endpoints
      owner: IT Operations
      addresses: CVE-2026-110108
      evidence: NVD vulnerability description
---

MateCloud versions up to 5.0.8 are affected by a critical authorization bypass vulnerability (CVE-2026-110108) located within the StorageController component. The vulnerability stems from missing authorization checks on the administrative API endpoints under /api/v1/admin/storage. Any authenticated user, regardless of their privilege level, can invoke these endpoints to interact with the underlying object storage system. This flaw allows unauthorized actors to list buckets, delete objects, upload arbitrary content, and retrieve pre-signed download URLs for files belonging to other users. The exposure of these management functions poses a significant risk to data confidentiality and integrity, as it enables low-privilege accounts to perform actions intended solely for administrative personnel.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to manipulate object storage environments without administrative rights. This can lead to the exfiltration of sensitive data through pre-signed URL generation, unauthorized deletion of critical assets, and the injection of malicious files into object storage buckets. The vulnerability is applicable to any deployment of MateCloud 5.0.8 or earlier.

## Recommendation

* Upgrade MateCloud to a patched version once available from the vendor to remediate CVE-2026-110108.
* Monitor web application access logs for any requests to the /api/v1/admin/storage path originating from non-administrative user accounts.
* Implement stricter network-level or identity-based access controls for administrative API endpoints to mitigate unauthorized access while awaiting a permanent patch.
