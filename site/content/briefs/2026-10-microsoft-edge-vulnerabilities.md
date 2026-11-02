---
brief_id: brief-2026-10-27-microsoft-edge-vulnerabilities
event_id: brief-2026-10-27-microsoft-edge-vulnerabilities
revision: 7
activity_at: "2026-11-02T15:30:33Z"
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
  - revision: 4
    at: "2026-10-29T20:15:56Z"
    checksum: sha256:ac1a81a6710b8a519114c1099665195de88d8507b673d8041bf2c54e02a95af6
    summary: new product
    changed_fields:
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62765
  - revision: 5
    at: "2026-10-29T20:19:26Z"
    checksum: sha256:5745dad30c89d6c275d67c90f374a3cfe267fb89904df500f80c871fb539ce8d
    summary: new product
    changed_fields:
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-96199
  - revision: 6
    at: "2026-10-30T21:22:22Z"
    checksum: sha256:f8134eef99a6de2310891be34422f0f86213f63a8b159dd06b9cd48e6044190e
    summary: added CVE-2026-85897 +1
    changed_fields:
      - cves
      - lastmod
      - priority_signals
      - references
      - updates
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69446
  - revision: 7
    at: "2026-11-02T15:30:33Z"
    checksum: sha256:e12bd76d670bf53f9baba3b98bd8e7326adbfa7ed4e3b52f3ed4d08e20be017e
    summary: added coverage for Edge
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - priority_signals
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4268
title: 'Microsoft Edge: Multiple Vulnerabilities'
slug: 2026-10-microsoft-edge-vulnerabilities
description: Multiple vulnerabilities in Microsoft Edge allow for remote code execution, privilege escalation, and unauthorized data access, requiring immediate updates to patched versions.
date: "2026-10-27T17:38:47Z"
lastmod: "2026-11-02T15:29:49Z"
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
  - privilege-escalation
  - microsoft-edge
vendors:
  - Microsoft
products:
  - Edge (< 155.0.4283.62)
  - Edge (< 154.0.4258.62)
  - Edge (< 154.0.8037.92)
  - Edge
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein lokaler Angreifer kann eine Schwachstelle in Microsoft Edge ausnutzen, um seine Privilegien zu erhöhen.
    confidence_band: high
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
    cvss: 8.8
    epss: 0.00767
    kev_status: "false"
  - id: CVE-2026-85897
    cvss: 8.8
    epss: 0.00586
    kev_status: "false"
  - id: CVE-2026-88078
    cvss: 4.3
    epss: 0.00298
    kev_status: "false"
  - id: CVE-2026-62765
    kev_status: unknown
  - id: CVE-2026-96199
    kev_status: unknown
  - id: CVE-2026-69446
    kev_status: unknown
  - id: CVE-2026-102299
    kev_status: unknown
  - id: CVE-2026-102302
    kev_status: unknown
  - id: CVE-2026-102305
    kev_status: unknown
  - id: CVE-2026-20942
    kev_status: unknown
  - id: CVE-2026-85890
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
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62765
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85890
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96199
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69446
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4268
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
    - CTI
  immediate_actions:
    - action: Monitor Microsoft Edge update channel for security patches referencing local privilege escalation.
      owner: IT Operations
      due: 7d
      evidence: BSI advisory indicates vulnerability requires patching.
  enrichment_needed:
    - item: CVE identifier
      owner: CTI
      reason: Necessary to track vulnerability lifecycle and vendor remediation status.
      evidence: Source is currently a general advisory.
  hunt_leads:
    - lead: Identify systems with outdated Edge installations that may be subject to future exploit disclosure.
      technique_id: T1068
      data_needed:
        - Endpoint software inventory
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: Local privilege escalation requires the vulnerable software to be present on the host.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Microsoft Edge to 155.0.4283.62 or 154.0.4258.62
      owner: IT Operations
      addresses: All CVEs listed in the advisory
      evidence: Source indicates updating to these versions resolves the identified vulnerabilities
    - priority: medium
      action: Apply future Microsoft Edge security updates once released.
      owner: IT Operations
      addresses: Local privilege escalation vulnerability
      evidence: BSI security advisory
updates:
  - at: "2026-10-29T20:14:34Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62765
  - at: "2026-10-29T20:17:53Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85890
  - at: "2026-10-29T20:18:31Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-96199
  - at: "2026-10-30T21:20:46Z"
    level: L2
    summary: added CVE-2026-85897 +1
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69446
  - at: "2026-11-02T15:29:49Z"
    level: L1
    summary: added coverage for Edge
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4268
---

The French cybersecurity agency (ANSSI/CERT-FR) has published an advisory detailing multiple security vulnerabilities affecting Microsoft Edge. These vulnerabilities include remote code execution (RCE), privilege escalation, and information disclosure. The affected versions are Microsoft Edge versions 155.x prior to 155.0.4283.62 and versions prior to 154.0.4258.62.

## Impact
Successful exploitation may allow attackers to execute arbitrary code with the privileges of the browser process, escalate privileges on the host system, or bypass security policies to access sensitive user data.

## Recommendation
- Update all instances of Microsoft Edge to version 155.0.4283.62 or 154.0.4258.62 immediately.
- Inventory browser versions across the enterprise to identify endpoints running affected builds.
- Prioritize the update on internet-facing systems and workstations used for high-value tasks.
