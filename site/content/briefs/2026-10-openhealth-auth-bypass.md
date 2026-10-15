---
title: Authentication and Authorization Bypass in OpenHealth
slug: 2026-10-openhealth-auth-bypass
description: OpenHealth versions 0.2.0 and earlier are vulnerable to unauthenticated access within the /api/health-data/ endpoint, allowing remote attackers to read, modify, or delete sensitive medical records.
date: "2026-10-15T22:50:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openhealth:openhealth:*:*:*:*:*:*:*:*
vendors:
  - OpenHealth
products:
  - OpenHealth (<= 0.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers who know a HealthData record id can read another user's medical record data and file metadata, overwrite it with arbitrary JSON, or delete it.
    confidence_band: high
cves:
  - id: CVE-2026-111312
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111312
rules:
  - title: Detect CVE-2026-111312 Exploitation - Unauthorized API Access
    description: Detects potential exploitation of CVE-2026-111312 by monitoring for API requests to the /api/health-data/ endpoint associated with DELETE or PATCH methods.
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
    - action: Upgrade OpenHealth to a patched version beyond 0.2.0.
      owner: IT Operations
      due: 48h
      evidence: Source identifies 0.2.0 as the affected version range.
  hunt_leads:
    - lead: Search logs for multiple 200 OK responses from unique source IPs targeting /api/health-data/* followed by PATCH or DELETE operations.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation involves unauthorized modification and deletion.
  mitigation_plan:
    - priority: immediate
      action: Implement network-level restrictions or WAF rules to block unauthorized access to /api/health-data/.
      owner: SOC
      addresses: CVE-2026-111312
      evidence: Missing authentication and authorization vulnerability.
---

OpenHealth versions 0.2.0 and earlier contain a critical missing authentication and authorization vulnerability in the /api/health-data/[id] endpoint. The affected handlers for GET, PATCH, and DELETE operations fail to validate user sessions or verify that the requested HealthData record belongs to the requester. An unauthenticated attacker who discovers or enumerates a valid record identifier can bypass security controls to access, alter, or destroy sensitive patient information. This vulnerability poses a significant risk to the confidentiality and integrity of medical data handled by the application. Because the flaw exists within the core API logic, it is trivial to exploit via standard HTTP requests once a valid record ID is identified.

## Impact

Successful exploitation allows unauthenticated attackers to exfiltrate private medical record data and metadata, overwrite existing patient records with arbitrary JSON payloads, or delete critical records entirely. This exposes patient health information to unauthorized parties and disrupts the availability of medical records, which may have legal, compliance, and clinical safety implications depending on the deployment environment.

## Recommendation

- Upgrade the OpenHealth application to a version released after 0.2.0 that includes patches for authentication enforcement.
- Audit access logs for high volumes of 200 OK responses to GET, PATCH, or DELETE requests targeting /api/health-data/* from unauthenticated or unexpected IP sources.
- Implement strict ingress filtering or network-level authentication (e.g., mTLS or API gateway validation) as a compensating control until the application can be patched.
- Use the webserver logs to monitor for excessive enumerative requests against the /api/health-data/ endpoint, which may indicate an attacker attempting to discover valid record IDs.
