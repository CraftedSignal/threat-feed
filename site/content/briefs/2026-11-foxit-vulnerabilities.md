---
brief_id: brief-2026-11-09-foxit-vulnerabilities
event_id: brief-2026-11-09-foxit-vulnerabilities
revision: 1
activity_at: "2026-11-09T22:11:21Z"
title: 'Foxit Workspace: SSRF and XSS vulnerabilities (CVE-2026-119431, CVE-2026-119432, CVE-2026-119433)'
slug: 2026-11-foxit-vulnerabilities
description: Multiple vulnerabilities in Foxit Workspace, identified as CVE-2026-119431, CVE-2026-119432, and CVE-2026-119433, allow for Server-Side Request Forgery (SSRF) and Cross-Site Scripting (XSS) attacks.
date: "2026-11-09T22:11:21Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:foxit:workspace:*:*:*:*:*:*:*:*
vendors:
  - Foxit
products:
  - Foxit Workspace
cves:
  - id: CVE-2026-119431
    cvss: 7.7
    epss: 0.0034
    kev_status: "false"
  - id: CVE-2026-119432
    cvss: 8.7
    epss: 0.00318
    kev_status: "false"
  - id: CVE-2026-119433
    cvss: 7.7
    epss: 0.0034
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1478/
  - https://www.foxitsoftware.com/support/security-bulletins.php
  - https://www.cve.org/CVERecord?id=CVE-2026-119431
  - https://www.cve.org/CVERecord?id=CVE-2026-119432
  - https://www.cve.org/CVERecord?id=CVE-2026-119433
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory Foxit Workspace deployments and verify patch status against vendor bulletin
      owner: IT Operations
      due: 24h
      evidence: Source advises referring to the vendor bulletin for patches
  mitigation_plan:
    - priority: immediate
      action: Apply patches provided by Foxit for identified CVEs
      owner: IT Operations
      addresses: CVE-2026-119431, CVE-2026-119432, CVE-2026-119433
      evidence: Source recommends referencing vendor bulletin for correction
---

The French National Cybersecurity Agency (ANSSI) has published an advisory regarding multiple vulnerabilities in Foxit Workspace. The flaws consist of Server-Side Request Forgery (SSRF) and Cross-Site Scripting (XSS) injection vectors. The vulnerabilities are tracked under CVE-2026-119431, CVE-2026-119432, and CVE-2026-119433. Users are advised to consult the official Foxit security bulletin for remediation steps and patch availability.

## Impact

Successful exploitation may allow an attacker to perform unauthorized SSRF actions against internal services or execute malicious scripts via XSS in the context of the user session.

## Recommendation

- Inventory all deployed instances of Foxit Workspace.
- Review the official Foxit security bulletins at https://www.foxitsoftware.com/support/security-bulletins.php.
- Apply security patches provided by the vendor for CVE-2026-119431, CVE-2026-119432, and CVE-2026-119433 immediately.
