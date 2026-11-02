---
brief_id: brief-2026-11-02-tenable-identity-exposure
event_id: brief-2026-11-02-tenable-identity-exposure
revision: 1
activity_at: "2026-11-02T15:34:20Z"
title: 'Tenable Identity Exposure: Multiple vulnerabilities (CVE-2026-119314, CVE-2026-119315, CVE-2026-119316)'
slug: 2026-11-tenable-identity-exposure
description: Tenable Identity Exposure is affected by multiple vulnerabilities that allow for remote code execution, denial-of-service, and data confidentiality breaches.
date: "2026-11-02T15:34:20Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Patch management verification required
tags:
  - vulnerability
  - remote-code-execution
  - denial-of-service
vendors:
  - Tenable
products:
  - Tenable Identity Exposure (< 3.77.18)
  - Tenable Identity Exposure (3.x < 3.93.6)
cves:
  - id: CVE-2026-119314
    kev_status: unknown
  - id: CVE-2026-119315
    kev_status: unknown
  - id: CVE-2026-119316
    kev_status: unknown
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1436/
  - https://www.tenable.com/security/tns-2026-34
  - https://www.cve.org/CVERecord?id=CVE-2026-119314
  - https://www.cve.org/CVERecord?id=CVE-2026-119315
  - https://www.cve.org/CVERecord?id=CVE-2026-119316
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Tenable Identity Exposure to versions 3.77.18+ or 3.93.6+
      owner: IT Operations
      due: 48h
      evidence: Tenable security bulletin tns-2026-34
  mitigation_plan:
    - priority: immediate
      action: Upgrade Tenable Identity Exposure to versions 3.77.18 or 3.93.6
      owner: IT Operations
      addresses: CVE-2026-119314, CVE-2026-119315, CVE-2026-119316
      evidence: Tenable security bulletin tns-2026-34
---

Tenable has released security bulletin tns-2026-34 addressing multiple vulnerabilities in Tenable Identity Exposure. These flaws can be leveraged by a remote attacker to execute arbitrary code, perform a denial-of-service, or gain unauthorized access to sensitive data. The identified CVEs include CVE-2026-119314, CVE-2026-119315, and CVE-2026-119316. 

## Impact

Successful exploitation may result in remote code execution, remote denial-of-service, or the compromise of data confidentiality within the affected Tenable Identity Exposure environment.

## Recommendation

Identify and patch all instances of Tenable Identity Exposure. Upgrade to the versions specified in the Tenable security bulletin tns-2026-34 (specifically version 3.77.18 or higher for 3.x branches earlier than 3.77.18, and 3.93.6 or higher for 3.x branches earlier than 3.93.6).
