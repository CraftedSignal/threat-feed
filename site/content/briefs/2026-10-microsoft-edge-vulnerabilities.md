---
brief_id: brief-2026-10-27-microsoft-edge-vulnerabilities
event_id: brief-2026-10-27-microsoft-edge-vulnerabilities
revision: 1
activity_at: "2026-10-27T17:38:47Z"
title: 'Microsoft Edge: Multiple Vulnerabilities'
slug: 2026-10-microsoft-edge-vulnerabilities
description: Multiple vulnerabilities in Microsoft Edge allow for remote code execution, privilege escalation, and unauthorized data access, requiring immediate updates to patched versions.
date: "2026-10-27T17:38:47Z"
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
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - browser
vendors:
  - Microsoft
products:
  - Edge (< 155.0.4283.62)
  - Edge (< 154.0.4258.62)
cves:
  - id: CVE-2026-102299
    kev_status: unknown
  - id: CVE-2026-102300
    kev_status: unknown
  - id: CVE-2026-102301
    kev_status: unknown
  - id: CVE-2026-102302
    kev_status: unknown
  - id: CVE-2026-102303
    kev_status: unknown
  - id: CVE-2026-102304
    cvss: 9.6
    epss: 0.00317
    kev_status: "false"
  - id: CVE-2026-102305
    kev_status: unknown
  - id: CVE-2026-102306
    cvss: 9.6
    epss: 0.00381
    kev_status: "false"
  - id: CVE-2026-102307
    kev_status: unknown
  - id: CVE-2026-102308
    kev_status: unknown
  - id: CVE-2026-102309
    kev_status: unknown
  - id: CVE-2026-102310
    cvss: 6.5
    epss: 0.00244
    kev_status: "false"
  - id: CVE-2026-102311
    kev_status: unknown
  - id: CVE-2026-102312
    kev_status: unknown
  - id: CVE-2026-102313
    cvss: 4.7
    epss: 0.00277
    kev_status: "false"
  - id: CVE-2026-102314
    kev_status: unknown
  - id: CVE-2026-102315
    kev_status: unknown
  - id: CVE-2026-102316
    kev_status: unknown
  - id: CVE-2026-102317
    cvss: 8.6
    epss: 0.00108
    kev_status: "false"
  - id: CVE-2026-83831
    kev_status: unknown
  - id: CVE-2026-85898
    kev_status: unknown
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1395/
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-83831
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-85898
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102299
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102300
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102301
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102302
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102303
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102304
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102305
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102306
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102307
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102308
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102309
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102310
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102311
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102312
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102313
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102314
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102315
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102316
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102317
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Microsoft Edge to 155.0.4283.62 or 154.0.4258.62
      owner: IT Operations
      addresses: All CVEs listed in the advisory
      evidence: Source indicates updating to these versions resolves the identified vulnerabilities
---

The French cybersecurity agency (ANSSI/CERT-FR) has published an advisory detailing multiple security vulnerabilities affecting Microsoft Edge. These vulnerabilities include remote code execution (RCE), privilege escalation, and information disclosure. The affected versions are Microsoft Edge versions 155.x prior to 155.0.4283.62 and versions prior to 154.0.4258.62.

## Impact
Successful exploitation may allow attackers to execute arbitrary code with the privileges of the browser process, escalate privileges on the host system, or bypass security policies to access sensitive user data.

## Recommendation
- Update all instances of Microsoft Edge to version 155.0.4283.62 or 154.0.4258.62 immediately.
- Inventory browser versions across the enterprise to identify endpoints running affected builds.
- Prioritize the update on internet-facing systems and workstations used for high-value tasks.
