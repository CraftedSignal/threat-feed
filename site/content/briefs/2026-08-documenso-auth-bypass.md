---
title: Authentication Bypass in Documenso File Upload Endpoint
slug: 2026-08-documenso-auth-bypass
description: Documenso versions prior to 2.13.0 allow unauthenticated attackers to perform arbitrary PDF file uploads via the /api/files/upload-pdf endpoint, potentially resulting in resource exhaustion.
date: "2026-08-29T17:41:10Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:documenso:documenso:*:*:*:*:*:*:*:*
vendors:
  - Documenso
products:
  - Documenso (< 2.13.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Unauthenticated attackers can upload arbitrary PDF files indefinitely to exhaust storage resources or fill the database with unlinked document records.
    confidence_band: high
cves:
  - id: CVE-2026-82472
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82472
rules:
  - title: Detect CVE-2026-82472 Exploitation - Unauthenticated File Uploads
    description: Detects unauthorized attempts to access the file upload endpoint which is subject to authentication bypass in versions prior to 2.13.0
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Documenso to 2.13.0
      owner: IT Operations
      due: 48h
      evidence: Source states Documenso before 2.13.0 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Implement WAF/ACL to block access to /api/files/upload-pdf
      owner: IT Operations
      addresses: CVE-2026-82472
      evidence: Vulnerability allows unauthenticated access to the specified endpoint
---

Documenso versions prior to 2.13.0 contain an authentication bypass vulnerability, tracked as CVE-2026-82472. The application fails to enforce authentication, session validation, or API credential requirements on the /api/files/upload-pdf endpoint. This allows any unauthenticated actor with network access to the Documenso instance to upload arbitrary PDF files.

Defenders should prioritize this vulnerability as it enables unauthorized resource consumption. Attackers can leverage this to exhaust disk storage or populate the application database with excessive unlinked document records, leading to a denial-of-service (DoS) condition. As this endpoint does not validate the source of the upload, it may also be used to bypass intended business workflows.

## Impact

Successful exploitation allows unauthenticated remote actors to cause a denial-of-service by overwhelming system resources. This impacts the availability and integrity of the document storage backend and database performance for all users of the affected Documenso instance.

## Recommendation

Prioritized actions for security teams:
- Upgrade all instances of Documenso to version 2.13.0 or later to apply the fix for CVE-2026-82472.
- Implement network-level access controls or a Web Application Firewall (WAF) to restrict access to the /api/files/upload-pdf endpoint to known, trusted IP ranges until patching is complete.
- Monitor web server access logs for anomalous, high-frequency POST requests to /api/files/upload-pdf originating from unauthorized or unexpected source IPs.
