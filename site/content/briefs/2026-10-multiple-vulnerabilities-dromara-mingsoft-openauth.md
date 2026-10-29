---
brief_id: brief-2026-10-29-multiple-vulnerabilities-dromara-mingsoft-openauth
event_id: brief-2026-10-29-multiple-vulnerabilities-dromara-mingsoft-openauth
revision: 1
activity_at: "2026-10-29T21:24:35Z"
title: Multiple Vulnerabilities in Dromara MaxKey, mingSoft MCMS, and OpenAuth.Net
slug: 2026-10-multiple-vulnerabilities-dromara-mingsoft-openauth
description: Multiple unauthenticated vulnerabilities were disclosed across Dromara MaxKey, mingSoft MCMS, and OpenAuth.Net, including XSS, information disclosure, and account takeover paths.
date: "2026-10-29T21:24:35Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
vendors:
  - Dromara
  - mingSoft
  - OpenAuth.Net
products:
  - MaxKey (4.x)
  - MCMS (6.1.1)
  - OpenAuth.Net (<= 8.3.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated arbitrary user password change via /api/dynamic/Invoke and sensitive information disclosure.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: GetList (CVE-2026-78832) dumps SysUser all plaintext credentials.
    confidence_band: high
cves:
  - id: CVE-2026-78829
    kev_status: unknown
  - id: CVE-2026-78830
    kev_status: unknown
  - id: CVE-2026-78831
    kev_status: unknown
  - id: CVE-2026-78832
    kev_status: unknown
references:
  - https://sploitus.com/exploit?id=1FAD72BC-AFFB-52E8-B935-E343D769A457
  - https://sploitus.com/exploit?id=1FAD72BC-AFFB-52E8-B935-E343D769A457&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review OpenAuth.Net logs for access to /api/dynamic/GetList and /api/dynamic/Invoke
      owner: SOC
      due: 24h
      evidence: Source document identifies these endpoints as the vector for full system takeover.
  hunt_leads:
    - lead: Identify anomalous requests to OpenAuth.Net API endpoints
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unauthenticated endpoints /api/dynamic/* are confirmed vectors for CVE-2026-78831 and CVE-2026-78832.
  mitigation_plan:
    - priority: immediate
      action: Patch or upgrade affected Dromara MaxKey, mingSoft MCMS, and OpenAuth.Net instances.
      owner: IT Operations
      addresses: CVE-2026-78829, CVE-2026-78830, CVE-2026-78831, CVE-2026-78832
      evidence: Source disclosure provides CVE IDs and vulnerable version ranges.
---

Public technical disclosures and proof-of-concept reproduction steps have been released for four CVEs affecting Dromara MaxKey, mingSoft MCMS, and OpenAuth.Net. The vulnerabilities include reflected and stored XSS, unauthenticated password modification, and sensitive information disclosure. A complete unauthenticated takeover chain was identified for OpenAuth.Net, potentially leading to RCE through an additional unauthenticated file upload capability.

## Attack Chain (OpenAuth.Net)

1. Attacker calls `/api/dynamic/GetList` (CVE-2026-78832) without authentication to dump the `SysUser` table.
2. Attacker retrieves plaintext administrative credentials from the dumped user data.
3. Attacker uses obtained credentials or the `/api/dynamic/Invoke` endpoint (CVE-2026-78831) to perform unauthorized password changes.
4. Attacker accesses the administrative interface using the compromised account.
5. Attacker interacts with the unauthenticated `/api/Files/Upload` endpoint.
6. Attacker uploads a malicious file to achieve remote code execution.
7. Attacker optionally calls `/api/dynamic/Delete` to remove audit logs for anti-forensics.

## Impact

- Dromara MaxKey 4.x: Reflected XSS enables admin session or JWT theft.
- mingSoft MCMS 6.1.1: Stored XSS allows malicious script injection via file uploads.
- OpenAuth.Net <= 8.3.4: Critical exposure allows full unauthenticated system takeover, data exfiltration, and arbitrary code execution.

## Recommendation

- Upgrade Dromara MaxKey, mingSoft MCMS, and OpenAuth.Net to versions addressing these vulnerabilities immediately.
- For OpenAuth.Net, enforce strict authentication and authorization checks on all `/api/dynamic/*` and `/api/Files/Upload` endpoints.
- Inspect web server logs for high volumes of requests to the `/api/dynamic/` path and unknown file uploads to `/api/Files/Upload`.
- Validate that no unauthorized users have been created or modified via administrative API endpoints.
