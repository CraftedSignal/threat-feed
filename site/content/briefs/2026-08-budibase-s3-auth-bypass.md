---
title: Budibase Authentication Bypass in S3 Attachment Endpoint
slug: 2026-08-budibase-s3-auth-bypass
description: An authorization vulnerability in Budibase <= 3.38.1 allows authenticated low-privileged users to generate arbitrary S3 pre-signed upload URLs using server-side datasource credentials.
date: "2026-08-26T14:20:07Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Budibase
products:
  - Budibase Server (<= 3.38.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated user with low-privileged 'BASIC' access can misuse server-side S3 datasource credentials to generate arbitrary pre-signed upload URLs.
    confidence_band: high
cves:
  - id: CVE-2026-54356
    cvss: 7.1
    epss: 0.00244
references:
  - https://github.com/advisories/GHSA-6x9p-4r67-5gjx
rules:
  - title: Detect Potential Unauthorized S3 URL Issuance - Budibase
    description: Detects unauthorized POST requests to the Budibase attachments API which could indicate exploitation of CVE-2026-54356.
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
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Budibase to 3.39.7 or later
      owner: IT Operations
      due: 48h
      evidence: Source advisory states vulnerability affects 3.38.1 and earlier
  hunt_leads:
    - lead: Search logs for POST requests to /api/attachments/ endpoint from low-privilege users
      technique_id: T1068
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this specific endpoint as the mechanism for the authorization bypass
  mitigation_plan:
    - priority: immediate
      action: Restrict S3 bucket policy permissions to the minimum necessary
      owner: IT Operations
      addresses: CVE-2026-54356
      evidence: Applying least privilege limits the potential damage from misused credentials
---

Budibase version 3.38.1 and earlier contains an authorization bypass vulnerability (CVE-2026-54356) that affects the `/api/attachments/:datasourceId/url` endpoint. Research confirms that while the development environment correctly enforces role-based access control, the published production environment fails to properly validate the 'BASIC' role permissions. An authenticated user assigned to a published application can invoke this endpoint to generate pre-signed S3 `PUT` URLs. 

Because the underlying application logic uses configured server-side datasource credentials to generate these URLs, the attacker can force the application to issue credentials for arbitrary S3 buckets and keys. This allows a low-privileged user to potentially upload, overwrite, or manipulate objects in storage environments accessible to the application's service principal or stored IAM credentials, effectively escalating their impact beyond the application's intended scope.

## Attack Chain

1. Attacker authenticates to a published Budibase application as a low-privileged user with the 'BASIC' role.
2. Attacker enumerates or identifies a valid `datasourceId` associated with an S3-compatible storage integration.
3. Attacker sends a `POST` request to `/api/attachments/<datasourceId>/url` targeting the vulnerable endpoint.
4. Attacker includes the required application headers, specifically `x-budibase-app-id`, to bypass initial routing constraints.
5. Attacker provides a JSON payload containing their chosen `bucket` and `key` values for the target S3 path.
6. The application performs an insufficient authorization check in `packages/server/src/middleware/authorized.ts`.
7. The server generates a pre-signed `PUT` URL using the backend S3 credentials and returns it to the attacker.
8. Attacker utilizes the signed URL to perform unauthorized file write operations against the target S3 infrastructure.

## Impact

The vulnerability allows unauthorized users to mint S3 upload credentials by leveraging the application's server-side identity. This enables unauthorized modification or injection of files into S3 buckets accessible by the application's configured credentials. Successful exploitation could lead to data integrity compromise or, if the application serves uploaded content, stored Cross-Site Scripting (XSS) or arbitrary code execution via file upload, depending on the downstream handling of the S3 objects.

## Recommendation

1. Upgrade Budibase to version 3.39.7 or later to implement proper authorization checks on the attachment API.
2. Audit S3 bucket policies for all datasources configured in Budibase to enforce the principle of least privilege, ensuring the application credentials cannot perform writes to unauthorized paths.
3. Deploy webserver logs monitoring for `POST` requests to `/api/attachments/*/url` that originate from users with the 'BASIC' role or other low-privilege accounts, and cross-reference these with subsequent outbound traffic to AWS S3 endpoints.
