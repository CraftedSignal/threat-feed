---
brief_id: brief-2026-10-27-microsoft-edge-vulnerabilities
event_id: brief-2026-10-27-microsoft-edge-vulnerabilities
revision: 3
activity_at: "2026-10-29T19:55:25Z"
revision_history:
  - revision: 2
    at: "2026-10-29T17:34:25Z"
    checksum: sha256:12a1ee82ec0fb2038eb119090eb99e0d77fd410a65c99367777fdf61e2f396e0
    summary: new product
    changed_fields:
      - affected_products
      - claim_state
      - cves
      - lastmod
      - priority_signals
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85897
  - revision: 3
    at: "2026-10-29T19:55:25Z"
    checksum: sha256:0bbeb4bf15d683edf839d1d16a318d940aa6120f5eb6bef23d0194f7440f8b66
    summary: new product
    changed_fields:
      - cpes
      - cves
      - lastmod
      - priority_signals
      - references
      - updates
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62765
title: 'Microsoft Edge: Multiple Vulnerabilities'
slug: 2026-10-microsoft-edge-vulnerabilities
description: Multiple vulnerabilities in Microsoft Edge allow for remote code execution, privilege escalation, and unauthorized data access, requiring immediate updates to patched versions.
date: "2026-10-27T17:38:47Z"
lastmod: "2026-10-29T19:54:00Z"
type: advisory
claim_state: <nil>
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
  - cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - browser
vendors:
  - Microsoft
products:
  - Edge (< 155.0.4283.62)
  - Edge (< 154.0.4258.62)
  - Edge (< 154.0.8037.92)
cves:
  - id: CVE-2026-102300
    kev_status: unknown
  - id: CVE-2026-102301
    cvss: 8.3
    epss: 0.00286
    kev_status: "false"
  - id: CVE-2026-102303
    cvss: 4.3
    epss: 0.00277
    kev_status: "false"
  - id: CVE-2026-102304
    cvss: 9.6
    epss: 0.00317
    kev_status: "false"
  - id: CVE-2026-102305
    cvss: 5.4
    epss: 0.00208
    kev_status: "false"
  - id: CVE-2026-102306
    cvss: 9.6
    epss: 0.00381
    kev_status: "false"
  - id: CVE-2026-102307
    kev_status: unknown
  - id: CVE-2026-102308
    cvss: 9.6
    epss: 0.00317
    kev_status: "false"
  - id: CVE-2026-102309
    cvss: 9.6
    epss: 0.00317
    kev_status: "false"
  - id: CVE-2026-102310
    cvss: 6.5
    epss: 0.00244
    kev_status: "false"
  - id: CVE-2026-102311
    kev_status: unknown
  - id: CVE-2026-102312
    cvss: 4.3
    epss: 0.00237
    kev_status: "false"
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
    cvss: 8.8
    epss: 0.00767
    kev_status: "false"
  - id: CVE-2026-85898
    kev_status: unknown
  - id: CVE-2026-85897
    kev_status: unknown
  - id: CVE-2026-62765
    kev_status: unknown
  - id: CVE-2026-102299
    kev_status: unknown
  - id: CVE-2026-102302
    kev_status: unknown
  - id: CVE-2026-88078
    kev_status: unknown
  - id: CVE-2026-20942
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
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4204
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85897
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-88078
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20942
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62765
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
updates:
  - at: "2026-10-29T17:33:47Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85897
  - at: "2026-10-29T19:53:13Z"
    level: L1
    summary: new product
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-88078
  - at: "2026-10-29T19:53:16Z"
    level: L1
    summary: new product
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20942
  - at: "2026-10-29T19:54:00Z"
    level: L1
    summary: new product
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62765
---

The French cybersecurity agency (ANSSI/CERT-FR) has published an advisory detailing multiple security vulnerabilities affecting Microsoft Edge. These vulnerabilities include remote code execution (RCE), privilege escalation, and information disclosure. The affected versions are Microsoft Edge versions 155.x prior to 155.0.4283.62 and versions prior to 154.0.4258.62.

## Impact
Successful exploitation may allow attackers to execute arbitrary code with the privileges of the browser process, escalate privileges on the host system, or bypass security policies to access sensitive user data.

## Recommendation
- Update all instances of Microsoft Edge to version 155.0.4283.62 or 154.0.4258.62 immediately.
- Inventory browser versions across the enterprise to identify endpoints running affected builds.
- Prioritize the update on internet-facing systems and workstations used for high-value tasks.
